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
#include	<unistd.h>

#include	<openssl/ssl.h>
#include	<openssl/err.h>

#include	<ts/ts.h>
#include	<ts/apidefs.h>

#include	<json.h>
#include	<curl/curl.h>

#include	"watcher.h"
#include	"api.h"
#include	"config.h"

static size_t watcher_handle_read(void *, size_t, size_t, void *);

#define	WT_READBUF_SZ	65535

struct watcher {
	k8s_config_t	*wt_config;
	char		*wt_resource;
	char		*wt_resource_version;

	watcher_callback_t
			 wt_callback;
	void		*wt_callbackdata;

	CURL		*wt_curl;
	char		*wt_buf;
	size_t		 wt_buflen;
	char		 wt_errbuf[CURL_ERROR_SIZE];
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

static void
watcher_curl_init(watcher_t wt) {
size_t			 len;
char			*s;
struct curl_slist	*hdrs = NULL;

	len = strlen(wt->wt_config->co_server) + strlen(wt->wt_resource)
		 + sizeof("?watch=true");
	s = malloc(len);
	snprintf(s, len, "%s%s?watch=true", wt->wt_config->co_server, wt->wt_resource);
	curl_easy_setopt(wt->wt_curl, CURLOPT_URL, s);
	free(s);

	if (wt->wt_config->co_token) {
		len = sizeof("Authorization: Bearer ")
			+ strlen(wt->wt_config->co_token);
		s = malloc(len);
		snprintf(s, len, "Authorization: Bearer %s", wt->wt_config->co_token);
		hdrs = curl_slist_append(hdrs, s);
	}

	if (hdrs)
		curl_easy_setopt(wt->wt_curl, CURLOPT_HTTPHEADER, hdrs);

	if (wt->wt_config->co_tls_certfile) {
		curl_easy_setopt(wt->wt_curl, CURLOPT_SSLCERTTYPE, "PEM");
		curl_easy_setopt(wt->wt_curl, CURLOPT_SSLCERT,
				 wt->wt_config->co_tls_certfile);
	}

	if (wt->wt_config->co_tls_keyfile) {
		curl_easy_setopt(wt->wt_curl, CURLOPT_SSLKEYTYPE, "PEM");
		curl_easy_setopt(wt->wt_curl, CURLOPT_SSLKEY,
				 wt->wt_config->co_tls_keyfile);
	}

	if (wt->wt_config->co_tls_cafile)
		curl_easy_setopt(wt->wt_curl, CURLOPT_CAINFO,
				 wt->wt_config->co_tls_cafile);

	if (wt->wt_config->co_tls_verify)
		curl_easy_setopt(wt->wt_curl, CURLOPT_SSL_VERIFYPEER, 1L);

	curl_easy_setopt(wt->wt_curl, CURLOPT_WRITEFUNCTION,
			 watcher_handle_read);
	curl_easy_setopt(wt->wt_curl, CURLOPT_WRITEDATA, wt);
	curl_easy_setopt(wt->wt_curl, CURLOPT_USERAGENT, "k8s-ts-ingress/0.0");
	curl_easy_setopt(wt->wt_curl, CURLOPT_ERRORBUFFER, wt->wt_errbuf);
}

watcher_t
watcher_create(k8s_config_t *conf, const char *resource)
{
watcher_t		 wt = NULL;

	assert(conf);
	assert(resource);

	if ((wt = calloc(1, sizeof(*wt))) == NULL) {
		TSError("[watcher] calloc: %s", strerror(errno));
		return NULL;
	}

	if ((wt->wt_resource = strdup(resource)) == NULL) {
		TSError("[watcher] strdup: %s", strerror(errno));
		watcher_free(wt);
		return NULL;
	}

	wt->wt_config = conf;

	if ((wt->wt_curl = curl_easy_init()) == NULL) {
		TSError("[watcher] %s: cannot create cURL handle",
			conf->co_server);
		watcher_free(wt);
		return NULL;
	}

	return wt;
}

static void
watcher_handle_line(watcher_t wt, const char *line)
{
json_object	*obj, *o, *metadata;
wt_event_type_t	 etype;
const char	*stype;

	TSDebug("watcher", "[%s] read line: %s",
		wt->wt_config->co_server, line);
	if ((obj = json_tokener_parse(line)) == NULL) {
		TSError("[watcher] %s: cannot parse JSON: %s",
			wt->wt_config->co_server, line);
		return;
	}

	if (!json_object_is_type(obj, json_type_object)) {
		TSError("[watcher] %s: JSON is not an object",
			wt->wt_config->co_server);
		json_object_put(obj);
		return;
	}

	if (!json_object_object_get_ex(obj, "type", &o)) {
		TSError("[watcher] %s: JSON object has no type",
			wt->wt_config->co_server);
		json_object_put(obj);
		return;
	}

	if (!json_object_is_type(o, json_type_string)) {
		TSError("[watcher] %s: JSON type is not a string",
			wt->wt_config->co_server);
		json_object_put(obj);
		return;
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
			wt->wt_config->co_server, stype);
		json_object_put(obj);
		return;
	}

	if (!json_object_object_get_ex(obj, "object", &o)) {
		TSError("[watcher] %s: JSON object has no object",
			wt->wt_config->co_server);
		json_object_put(obj);
		return;
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
}

static size_t
watcher_handle_read(void *data, size_t sz, size_t n, void *udata)
{
watcher_t	 wt = udata;
size_t		 nread = sz * n;
char		*s;
char		*bufptr, *bufend;

	if (nread == 0)
		return 0;

	/* Copy the new data into our buffer */
	wt->wt_buf = realloc(wt->wt_buf, wt->wt_buflen + nread);
	bcopy(data, wt->wt_buf + wt->wt_buflen, nread);
	wt->wt_buflen += nread;

	bufptr = wt->wt_buf;
	bufend = bufptr + wt->wt_buflen;

	/* Process any complete lines we've read */
	while ((s = memchr(bufptr, '\n', (bufend - bufptr))) != NULL) {
		*s = '\0';
		watcher_handle_line(wt, bufptr);
		bufptr = s + 1;
	}

	memmove(wt->wt_buf, bufptr, (bufend - bufptr));
	wt->wt_buflen = (bufend - bufptr);

	return nread;
}

void *
watcher_thread(void *data)
{
watcher_t	wt = data;

	for (;;) {
	CURLcode	res;
		watcher_curl_init(wt);
		res = curl_easy_perform(wt->wt_curl);

		if (res != CURLE_OK) {
			TSDebug("watcher", "[%s] cURL error: %s",
				wt->wt_config->co_server, wt->wt_errbuf);
			TSError("[%s] %s",
				wt->wt_config->co_server, wt->wt_errbuf);
		}

		sleep(5);
	}

	return NULL;
}

int
watcher_run(watcher_t wt, int delay)
{
	TSDebug("watcher", "[%s]: starting", wt->wt_config->co_server);
	TSThreadCreate(watcher_thread, wt);
	return 0;
}

void
watcher_set_callback(watcher_t wt, watcher_callback_t cb, void *cbdata)
{
	wt->wt_callback = cb;
	wt->wt_callbackdata = cbdata;
}

void
watcher_free(watcher_t wt)
{
	if (wt->wt_curl)
		curl_easy_cleanup(wt->wt_curl);

	free(wt->wt_buf);
	free(wt);
}
