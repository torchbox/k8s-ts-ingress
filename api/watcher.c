/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<sys/types.h>

#include	<netinet/in.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<errno.h>
#include	<string.h>
#include	<assert.h>

#include	<openssl/ssl.h>
#include	<openssl/err.h>

#include	<ts/ts.h>
#include	<ts/apidefs.h>

#include	<json.h>

#include	"watcher.h"
#include	"api.h"
#include	"config.h"

static int	handler(TSCont, TSEvent, void *);
static void	watcher_reconnect(watcher_t);
static int	watcher_h_connect(watcher_t);
static int	watcher_h_send_request(watcher_t);
static int	watcher_h_read_response(watcher_t);

typedef int (*watcher_handler) (watcher_t);

#define	WT_READBUF_SZ	65535

typedef enum {
	WT_NOT_STARTED,
	WT_WANT_READ,
	WT_WANT_WRITE,
	WT_RUNNING
} wt_state_t;

struct watcher {
	k8s_config_t	*wt_config;
	char		*wt_resource;
	char		*wt_resource_version;

	watcher_callback_t
			 wt_callback;
	void		*wt_callbackdata;

	TSCont		 wt_contn;
	TSVConn		 wt_vconn;

	TSVIO		 wt_readvio;
	TSIOBuffer	 wt_readbuf;
	TSIOBufferReader wt_readbuf_reader;
	BIO		*wt_read_bio;

	TSVIO		 wt_writevio;
	TSIOBuffer	 wt_writebuf;
	TSIOBufferReader wt_writebuf_reader;
	BIO		*wt_write_bio;

	SSL_CTX		*wt_ssl_ctx;
	SSL		*wt_ssl;

	wt_state_t	 wt_state;
	watcher_handler	 wt_handler;

	char		*wt_requestbuf;
	char		*wt_request;
	size_t		 wt_requestsz;

	int		 wt_read_headers;

	char		 wt_buf[WT_READBUF_SZ + 1];
	size_t		 wt_bufsz;
};

char *
_k8s_get_ssl_error(void)
{
BIO	*bio = BIO_new(BIO_s_mem());
size_t	 len;
char	*ret, *buf;

	ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &buf);
	if (len == 0) {
		BIO_free(bio);
		return strdup("no error");
	}

	if ((ret = malloc(len + 1)) == NULL) {
		BIO_free(bio);
		return NULL;
	}

	bcopy(buf, ret, len);
	buf[len] = '\0';
	BIO_free(bio);
	return ret;
}

watcher_t
watcher_create(k8s_config_t *conf, const char *resource)
{
watcher_t	wt = NULL;

	assert(conf);
	assert(resource);

	if ((wt = calloc(1, sizeof(*wt))) == NULL) {
		TSError("[watcher] calloc: %s", strerror(errno));
		return NULL;
	}

	if ((wt->wt_resource = strdup(resource)) == NULL) {
		TSError("[watcher] strdup: %s", strerror(errno));
		free(wt);
		return NULL;
	}

	wt->wt_config = conf;
	wt->wt_handler = watcher_h_connect;
	wt->wt_state = WT_RUNNING;
	return wt;
}

static void
watcher_reconnect(watcher_t wt)
{
	TSContDataSet(wt->wt_contn, NULL);
	if (wt->wt_vconn) {
		TSVConnClose(wt->wt_vconn);
		wt->wt_vconn = NULL;
	}
	TSContDestroy(wt->wt_contn);

	wt->wt_contn = NULL;
	if (wt->wt_ssl_ctx) {
		SSL_CTX_free(wt->wt_ssl_ctx);
		wt->wt_ssl_ctx = NULL;
	}

	if (wt->wt_ssl) {
		SSL_free(wt->wt_ssl);
		wt->wt_ssl = NULL;
	}

	if (wt->wt_read_bio)
		wt->wt_read_bio = NULL;
	if (wt->wt_write_bio)
		wt->wt_write_bio = NULL;

	if (wt->wt_requestbuf) {
		free(wt->wt_requestbuf);
		wt->wt_requestbuf = NULL;
	}

	wt->wt_request = NULL;
	wt->wt_requestsz = 0;
	wt->wt_bufsz = 0;
	wt->wt_read_headers = 0;
	watcher_run(wt, 5);
}

static int
watcher_handle_read(watcher_t wt)
{
char	*s;

	if (!wt->wt_read_headers) {
	char	*eoh;
	int	 maj, min;
	int	 status;
	char	*statustext;
	size_t	 hdrlen;

		TSDebug("watcher", "[%s] watcher_handle_read: no headers yet",
			wt->wt_config->co_host);

		if ((eoh = strstr(wt->wt_buf, "\r\n\r\n")) == NULL) {
			TSDebug("watcher", "[%s] watcher_handle_read: still no headers",
				wt->wt_config->co_host);
			return 0;
		}

		*eoh = 0;
		if (sscanf(wt->wt_buf, "HTTP/%d.%d %d %ms\r\n",
			   &maj, &min, &status, &statustext) != 4) {
			TSError("[watcher] %s: did not receive HTTP status",
				wt->wt_config->co_host);
			return -1;
		}

		TSDebug("watcher", "[%s] got HTTP status %d %s",
			wt->wt_config->co_host, status, statustext);
		free(statustext);
		wt->wt_read_headers = 1;

		hdrlen = (eoh - wt->wt_buf) + 4;
		memmove(wt->wt_buf, wt->wt_buf + hdrlen, wt->wt_bufsz - hdrlen + 1);
		wt->wt_bufsz -= hdrlen;

		if (status != 200) {
			TSError("[watcher] %s: HTTP error %d; will retry",
				wt->wt_config->co_host, status);
			watcher_reconnect(wt);
			return -1;
		}
	}

	TSDebug("watcher", "[%s] watcher_handle_read: data: [%s]",
		wt->wt_config->co_host, wt->wt_buf);

	while ((s = strchr(wt->wt_buf, '\n')) != NULL) {
	size_t		 linelen;
	json_object	*obj, *o, *metadata;
	wt_event_type_t	 etype;
	const char	*stype;

		linelen = (s - wt->wt_buf) + 1;
		*s = '\0';

		TSDebug("watcher", "[%s] read line: %s", wt->wt_config->co_host, wt->wt_buf);
		if ((obj = json_tokener_parse(wt->wt_buf)) == NULL) {
			TSError("[watcher] %s: cannot parse JSON: %s",
				wt->wt_config->co_host, wt->wt_buf);
			continue;
		}

		if (!json_object_is_type(obj, json_type_object)) {
			TSError("[watcher] %s: JSON is not an object", wt->wt_config->co_host);
			json_object_put(obj);
			continue;
		}

		if (!json_object_object_get_ex(obj, "type", &o)) {
			TSError("[watcher] %s: JSON object has no type", wt->wt_config->co_host);
			json_object_put(obj);
			continue;
		}

		if (!json_object_is_type(o, json_type_string)) {
			TSError("[watcher] %s: JSON type is not a string",
				wt->wt_config->co_host);
			json_object_put(obj);
			continue;
		}

		stype = json_object_get_string(o);
		if (strcmp(stype, "ADDED") == 0)
			etype = WT_ADDED;
		else if (strcmp(stype, "MODIFIED") == 0)
			etype = WT_UPDATED;
		else if (strcmp(stype, "DELETED") == 0)
			etype = WT_DELETED;
		else {
			TSError("[watcher] %s: unrecognised event type %s",
				wt->wt_config->co_host, stype);
			json_object_put(obj);
			continue;
		}

		if (!json_object_object_get_ex(obj, "object", &o)) {
			TSError("[watcher] %s: JSON object has no object",
				wt->wt_config->co_host);
			json_object_put(obj);
			continue;
		}

		if (json_object_object_get_ex(obj, "metadata", &metadata)) {
		json_object	*rversion;
			if (json_object_object_get_ex(metadata, "resourceVersion",
						      &rversion)) {
				if (wt->wt_resource_version)
					free(wt->wt_resource_version);
				wt->wt_resource_version = strdup(
					json_object_get_string(rversion));
			}
		}

		wt->wt_callback(wt, etype, o, wt->wt_callbackdata);

		json_object_put(obj);
		memmove(wt->wt_buf, wt->wt_buf + linelen, wt->wt_bufsz - linelen + 1);
		wt->wt_bufsz -= linelen;
	}

	return 0;
}

static int
watcher_h_read_response(watcher_t wt)
{
	TSDebug("watcher", "[%s] reading response", wt->wt_config->co_host);

	for (;;) {
	int	ret;
		TSDebug("watcher", "[%s] SSL_read, pending=%d, wpending=%d",
			wt->wt_config->co_host,
			(int) BIO_pending(wt->wt_read_bio),
			(int) BIO_pending(wt->wt_write_bio));

		if ((WT_READBUF_SZ - wt->wt_bufsz) == 0) {
			TSError("[watcher] %s: readbuf is full, cannot continue",
				wt->wt_config->co_host);
			watcher_reconnect(wt);
			return -1;
		}

		ret = SSL_read(wt->wt_ssl, 
			       wt->wt_buf + wt->wt_bufsz,
			       WT_READBUF_SZ - wt->wt_bufsz);

		if (ret > 0) {
			TSDebug("watcher", "[%s] read data: [%*s]",
				wt->wt_config->co_host, ret, wt->wt_buf + wt->wt_bufsz);
			wt->wt_bufsz += ret;
			wt->wt_buf[wt->wt_bufsz] = '\0';

			if (watcher_handle_read(wt) == -1)
				return -1;
			continue;
		}

		if (ret == 0) {
			TSError("[watcher] %s: SSL read error: %s", wt->wt_config->co_host,
				_k8s_get_ssl_error());
			watcher_reconnect(wt);
			return -1;
		}

		if (ret < 0) {
			switch (ret = SSL_get_error(wt->wt_ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				TSDebug("watcher", "[%s] SSL_read wants read, "
					"pending=%d, wpending=%d",
					wt->wt_config->co_host,
					(int) BIO_pending(wt->wt_read_bio),
					(int) BIO_pending(wt->wt_write_bio));
				wt->wt_state = WT_WANT_READ;
				return 0;

			case SSL_ERROR_WANT_WRITE:
				wt->wt_state = WT_WANT_WRITE;
				TSDebug("watcher", "[%s] SSL_read wants write",
					wt->wt_config->co_host);
				return 0;

			default:
				TSError("[watcher] %s: SSL error %d",
					wt->wt_config->co_host, ret);
				return 0;
			}
		}
	}
}

static int
watcher_h_send_request(watcher_t wt)
{
int	ret = 0;

	if (wt->wt_request == NULL) {
	char	version[128] = {};
		if (wt->wt_resource_version)
			snprintf(version, sizeof(version), "&resourceVersion=%s",
				 wt->wt_resource_version);

		wt->wt_requestbuf = calloc(1024, 1);
		wt->wt_request = wt->wt_requestbuf;

		if (wt->wt_config->co_token)
			wt->wt_requestsz = snprintf(wt->wt_requestbuf, 1024,
				 "GET %s?watch=true%s HTTP/1.0\r\n"
				 "Host: %s\r\n"
				 "Authorization: Bearer %s\r\n\r\n",
				 wt->wt_resource, version, wt->wt_config->co_host,
				 wt->wt_config->co_token);
		else
			wt->wt_requestsz = snprintf(wt->wt_requestbuf, 1024,
				 "GET %s?watch=true%s HTTP/1.0\r\n"
				 "Host: %s\r\n\r\n",
				 wt->wt_resource, version, wt->wt_config->co_host);

		TSDebug("watcher", "[%s] request: [%s]",
			wt->wt_config->co_host, wt->wt_request);
	}

	TSDebug("watcher", "[%s] sending request", wt->wt_config->co_host);

	while (wt->wt_requestsz > 0) {
		ret = SSL_write(wt->wt_ssl, wt->wt_request, wt->wt_requestsz);
		if (ret > 0) {
			wt->wt_request += ret;
			wt->wt_requestsz -= ret;
			continue;
		}

		if (ret == 0) {
			TSError("[watcher] %s: SSL write error: %s", wt->wt_config->co_host,
				_k8s_get_ssl_error());
			watcher_reconnect(wt);
			return -1;
		}

		switch (ret = SSL_get_error(wt->wt_ssl, ret)) {
		case SSL_ERROR_WANT_READ:
			TSDebug("watcher", "[%s] SSL_write wants read, "
				"pending=%d, wpending=%d",
				wt->wt_config->co_host,
				(int) BIO_pending(wt->wt_read_bio),
				(int) BIO_pending(wt->wt_write_bio));
			wt->wt_state = WT_WANT_READ;
			return 0;

		case SSL_ERROR_WANT_WRITE:
			TSDebug("watcher", "[%s] SSL_write wants write",
				wt->wt_config->co_host);
			wt->wt_state = WT_WANT_WRITE;
			return 0;

		default:
			TSError("[watcher] %s: SSL error %d", wt->wt_config->co_host, ret);
			return 0;
		}
	}

	TSDebug("watcher", "[%s] finished sending request %d",
		wt->wt_config->co_host, (int) ret);

	wt->wt_handler = watcher_h_read_response;
	wt->wt_state = WT_RUNNING;
	return 0;
}

static int
watcher_h_connect(watcher_t wt)
{
int	ret;

	if (wt->wt_ssl == NULL) {
		wt->wt_ssl = SSL_new(wt->wt_ssl_ctx);
		wt->wt_write_bio = BIO_new(BIO_s_mem());
		wt->wt_read_bio = BIO_new(BIO_s_mem());
		wt->wt_ssl = SSL_new(wt->wt_ssl_ctx);
		SSL_set_bio(wt->wt_ssl, wt->wt_read_bio, wt->wt_write_bio);
	}

	TSDebug("watcher", "[%s] watcher_h_connect, pending=%d, wpending=%d",
		wt->wt_config->co_host,
		(int) BIO_pending(wt->wt_read_bio),
		(int) BIO_pending(wt->wt_write_bio));

	switch (ret = SSL_connect(wt->wt_ssl)) {
	case 1:
		TSDebug("watcher", "[%s] SSL_connect done", wt->wt_config->co_host);
		wt->wt_handler = watcher_h_send_request;
		wt->wt_state = WT_RUNNING;
		return 0;

	case 0:
		TSError("[watcher] %s: SSL error: %s", wt->wt_config->co_host,
			_k8s_get_ssl_error());
		watcher_reconnect(wt);
		return -1;
	}

	switch (ret = SSL_get_error(wt->wt_ssl, ret)) {
	case SSL_ERROR_WANT_READ:
		TSDebug("watcher", "[%s] SSL_connect wants read, "
			"pending=%d, wpending=%d",
			wt->wt_config->co_host,
			(int) BIO_pending(wt->wt_read_bio),
			(int) BIO_pending(wt->wt_write_bio));
		wt->wt_state = WT_WANT_READ;
		return 0;

	case SSL_ERROR_WANT_WRITE:
		TSDebug("watcher", "[%s] OpenSSL wants write", wt->wt_config->co_host);
		wt->wt_state = WT_WANT_WRITE;
		return 0;

	default:
		TSError("[watcher] %s: SSL error %d", wt->wt_config->co_host, ret);
		return 0;
	}
}

int
watcher_run(watcher_t wt, int delay)
{
	TSDebug("watcher", "creating continuation for %s", wt->wt_config->co_host);

	if ((wt->wt_ssl_ctx = SSL_CTX_new(SSLv23_method())) == NULL) {
	char	*err = _k8s_get_ssl_error();
		TSError("[watcher] SSL_CTX_new failed: %s", err);
		free(err);
		return -1;
	}

	if (wt->wt_config->co_tls_cafile) {
		if (SSL_CTX_load_verify_locations(wt->wt_ssl_ctx,
					wt->wt_config->co_tls_cafile,
					NULL) == 0) {
		char	*err = _k8s_get_ssl_error();
			TSError("[watcher] Cannot load CA file %s: %s",
				wt->wt_config->co_tls_cafile, err);
			free(err);
			return -1;
		}
	}

	if (wt->wt_config->co_tls_certfile) {
		if (SSL_CTX_use_certificate_file(wt->wt_ssl_ctx,
						 wt->wt_config->co_tls_certfile,
						 SSL_FILETYPE_PEM) == 0) {
		char	*err = _k8s_get_ssl_error();
			TSError("[watcher] Cannot load certificate %s: %s",
				wt->wt_config->co_tls_certfile, err);
			free(err);
			return -1;
		}
	}

	if (wt->wt_config->co_tls_keyfile) {
		if (SSL_CTX_use_PrivateKey_file(wt->wt_ssl_ctx,
						wt->wt_config->co_tls_keyfile,
						SSL_FILETYPE_PEM) == 0) {
		char	*err = _k8s_get_ssl_error();
			TSError("[watcher] Cannot load key %s: %s",
				wt->wt_config->co_tls_keyfile, err);
			free(err);
			return -1;
		}
	}

	if ((wt->wt_contn = TSContCreate(handler, TSMutexCreate())) == NULL) {
		TSError("[watcher] cannot create continuation");
		return -1;
	}

	wt->wt_state = WT_NOT_STARTED;
	wt->wt_handler = watcher_h_connect;
	TSContDataSet(wt->wt_contn, wt);
	TSContSchedule(wt->wt_contn, delay * 1000, TS_THREAD_POOL_DEFAULT);
	return 0;
}

void
watcher_flush(watcher_t wt)
{
char	buf[8192];
int	n;

	TSDebug("watcher", "[%s] watcher_flush", wt->wt_config->co_host);

	/* Write any pending data from OpenSSL */
	if ((n = BIO_read(wt->wt_write_bio, buf, sizeof(buf))) > 0) {
		TSDebug("watcher", "[%s] writing %d bytes data to vconn",
			wt->wt_config->co_host, (int) n);
		TSIOBufferWrite(wt->wt_writebuf, buf, n);
		TSVIOReenable(wt->wt_writevio);
	}

	while (TSIOBufferReaderAvail(wt->wt_readbuf_reader) > 0) {
	TSIOBufferBlock	 blk;
	const char	*rbuf;
	int64_t		 nread;

		blk = TSIOBufferReaderStart(wt->wt_readbuf_reader);
		rbuf = TSIOBufferBlockReadStart(blk, wt->wt_readbuf_reader, &nread);
		n = BIO_write(wt->wt_read_bio, rbuf, nread);
		TSDebug("watcher", "[%s] read %d of %d bytes data for bio",
			wt->wt_config->co_host, (int) n, (int) nread);
		TSIOBufferReaderConsume(wt->wt_readbuf_reader, n);
		if (n != nread)
			break;
	}
	TSVIOReenable(wt->wt_readvio);
}

static int
handler(TSCont contn, TSEvent event, void *data)
{
watcher_t		 wt = TSContDataGet(contn);
const struct sockaddr	*addr;
struct sockaddr_in	 sin;
struct sockaddr_in6	 sin6;

	if (wt == NULL) {
		TSDebug("watcher", "handler called with null data");
		return 0;
	}

	switch (event) {
	case TS_EVENT_TIMEOUT:
		if (wt->wt_state != WT_NOT_STARTED) {
			TSError("[watcher] %s: timeout", wt->wt_config->co_host);
			watcher_reconnect(wt);
			return 0;
		}

	case TS_EVENT_IMMEDIATE:
		TSDebug("watcher", "[%s] beginning DNS lookup", wt->wt_config->co_host);
		TSHostLookup(contn, wt->wt_config->co_host, strlen(wt->wt_config->co_host));
		break;
	
	case TS_EVENT_HOST_LOOKUP:
		if (!data) {
			TSError("[watcher] %s: host looked failed", wt->wt_config->co_host);
			TSContSchedule(contn, 5000, TS_THREAD_POOL_DEFAULT);
			return 0;
		}

		TSDebug("watcher", "[%s:%d] host lookup finished; connecting",
			wt->wt_config->co_host, wt->wt_config->co_port);

		addr = TSHostLookupResultAddrGet(data);
		switch (addr->sa_family) {
		case AF_INET:
			bzero(&sin, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_port = htons(wt->wt_config->co_port);
			bcopy(&((const struct sockaddr_in *)addr)->sin_addr,
			      &sin.sin_addr, sizeof(sin.sin_addr));
			TSNetConnect(contn, (struct sockaddr *)&sin);
			break;

		case AF_INET6:
			bzero(&sin6, sizeof(sin6));
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = htons(wt->wt_config->co_port);
			bcopy(&((const struct sockaddr_in6 *)addr)->sin6_addr,
			      &sin6.sin6_addr, sizeof(sin6.sin6_addr));
			TSNetConnect(contn, (struct sockaddr *)&sin6);
			break;

		default:
			TSError("[watcher] %s: unknown address family: %d",
				wt->wt_config->co_host, (int) addr->sa_family);
			TSContSchedule(contn, 5000, TS_THREAD_POOL_DEFAULT);
			return 0;
		}

		break;

	case TS_EVENT_NET_CONNECT_FAILED:
		TSError("[watcher] %s: could not connect", wt->wt_config->co_host);
		TSContSchedule(contn, 5000, TS_THREAD_POOL_DEFAULT);
		break;

	case TS_EVENT_NET_CONNECT:
		TSDebug("watcher", "[%s] connected to apiserver", wt->wt_config->co_host);
		wt->wt_vconn = data;

		wt->wt_readbuf = TSIOBufferCreate();
		wt->wt_readbuf_reader = TSIOBufferReaderAlloc(wt->wt_readbuf);
		wt->wt_readvio = TSVConnRead(wt->wt_vconn, contn,
					     wt->wt_readbuf, INT64_MAX);

		wt->wt_writebuf = TSIOBufferCreate();
		wt->wt_writebuf_reader = TSIOBufferReaderAlloc(wt->wt_writebuf);
		wt->wt_writevio = TSVConnWrite(wt->wt_vconn, contn,
					     wt->wt_writebuf_reader, INT64_MAX);

		if (wt->wt_handler(wt) == -1)
			return 0;

		watcher_flush(wt);
		break;

	case TS_EVENT_VCONN_READ_READY:
		TSDebug("watcher", "[%s] vconn read ready", wt->wt_config->co_host);

		watcher_flush(wt);
		do {
			if (wt->wt_handler(wt) == -1)
				return 0;
			watcher_flush(wt);
		} while (wt->wt_state == WT_RUNNING);
		break;

	case TS_EVENT_VCONN_WRITE_READY:
		TSDebug("watcher", "[%s] vconn write ready", wt->wt_config->co_host);
		watcher_flush(wt);
		do {
			if (wt->wt_handler(wt) == -1)
				return 0;
			watcher_flush(wt);
		} while (wt->wt_state == WT_RUNNING);
		break;

	case TS_EVENT_VCONN_EOS:
		TSDebug("watcher", "[%s] connection closed", wt->wt_config->co_host);
		watcher_reconnect(wt);
		return 0;

	default:
		TSDebug("watcher", "[%s] received unknown event %d",
			wt->wt_config->co_host, (int) event);
		break;
	}

	return 0;
}

void
watcher_set_callback(watcher_t wt, watcher_callback_t cb, void *cbdata)
{
	wt->wt_callback = cb;
	wt->wt_callbackdata = cbdata;
}
