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
#include	"autoconf.h"

/*
 * How often to discard the current cluster state and re-fetch everything from
 * the API server.
 */
#define	RESYNC_INTERVAL	300

struct resource {
	const char	*url;
	char		*version;
} resources[] = {
	{ "/api/v1/services", 			NULL },
	{ "/api/v1/endpoints",			NULL },
	{ "/api/v1/secrets",			NULL },
	{ "/apis/extensions/v1beta1/ingresses",	NULL },
};
#define NRESOURCES (sizeof(resources) / sizeof(*resources))

struct watcher {
	k8s_config_t	*wt_config;
	cluster_t	*wt_cluster;

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

static CURL *
watcher_make_curl(const watcher_t *wt, char *errbuf, struct curl_slist **hdrs,
		  curl_write_callback cb, void *cbdata) {
size_t			 len;
char			*s;
CURL			*ret;

	if ((ret = curl_easy_init()) == NULL) {
		TSError("watcher_make_curl: curl_easy_init() failed");
		return NULL;
	}

	if (wt->wt_config->co_token) {
		len = sizeof("Authorization: Bearer ")
			+ strlen(wt->wt_config->co_token) + 1;
		s = malloc(len);
		snprintf(s, len, "Authorization: Bearer %s",
			 wt->wt_config->co_token);
		*hdrs = curl_slist_append(*hdrs, s);
		free(s);
	}

	if (*hdrs)
		curl_easy_setopt(ret, CURLOPT_HTTPHEADER, *hdrs);

	if (wt->wt_config->co_tls_certfile) {
		curl_easy_setopt(ret, CURLOPT_SSLCERTTYPE, "PEM");
		curl_easy_setopt(ret, CURLOPT_SSLCERT,
				 wt->wt_config->co_tls_certfile);
	}

	if (wt->wt_config->co_tls_keyfile) {
		curl_easy_setopt(ret, CURLOPT_SSLKEYTYPE, "PEM");
		curl_easy_setopt(ret, CURLOPT_SSLKEY,
				 wt->wt_config->co_tls_keyfile);
	}

	if (wt->wt_config->co_tls_cafile)
		curl_easy_setopt(ret, CURLOPT_CAINFO,
				 wt->wt_config->co_tls_cafile);

	if (wt->wt_config->co_tls_verify)
		curl_easy_setopt(ret, CURLOPT_SSL_VERIFYPEER, 1L);
	else
		curl_easy_setopt(ret, CURLOPT_SSL_VERIFYPEER, 0L);

	curl_easy_setopt(ret, CURLOPT_WRITEFUNCTION, cb);
	curl_easy_setopt(ret, CURLOPT_WRITEDATA, cbdata);
	curl_easy_setopt(ret, CURLOPT_USERAGENT,
			 "k8s-ts-ingress/" PACKAGE_VERSION);
	curl_easy_setopt(ret, CURLOPT_ERRORBUFFER, errbuf);
	return ret;
}

watcher_t *
watcher_create(k8s_config_t *conf, cluster_t *cluster)
{
watcher_t	*wt = NULL;

	assert(conf);
	assert(cluster);

	if ((wt = calloc(1, sizeof(*wt))) == NULL) {
		TSError("[watcher] calloc: %s", strerror(errno));
		return NULL;
	}

	wt->wt_config = conf;
	wt->wt_cluster = cluster;

	return wt;
}

struct fetcher_ctx {
	watcher_t		*watcher;
	struct resource		*resource;
	CURL			*curl;
	struct curl_slist	*hdrs;
	char			 errbuf[CURL_ERROR_SIZE];
	char			*url;
	char			*buf;
	size_t			 buflen;
	int			 changed;
};

static size_t
fe_read(char *data, size_t sz, size_t n, void *udata)
{
struct fetcher_ctx	*fe = udata;
size_t			 nread = sz * n;

	TSDebug("watcher", "fe_read: read %d", (int) nread);

	if (nread == 0)
		return 0;

	fe->buf = realloc(fe->buf, fe->buflen + nread + 1);
	bcopy(data, fe->buf + fe->buflen, nread);
	fe->buflen += nread;
	return nread;
}

static void
fe_watch_line(struct fetcher_ctx *fe, const char *line)
{
json_object	*obj, *o, *metadata, *kind, *namespace, *name;
const char	*stype, *skind, *sname;
int		 deleted = 0;
namespace_t	*ns;

	TSDebug("watcher", "fe_watch_line: read line: %s", line);

	if ((obj = json_tokener_parse(line)) == NULL) {
		TSError("[watcher] cannot parse JSON: %s", line);
		return;
	}

	if (!json_object_is_type(obj, json_type_object)) {
		TSError("[watcher] JSON is not an object");
		json_object_put(obj);
		return;
	}

	if (!json_object_object_get_ex(obj, "type", &o)) {
		TSError("[watcher] JSON object has no type");
		json_object_put(obj);
		return;
	}

	if (!json_object_is_type(o, json_type_string)) {
		TSError("[watcher] JSON type is not a string");
		json_object_put(obj);
		return;
	}

	stype = json_object_get_string(o);
	if (strcmp(stype, "DELETED") == 0)
		deleted = 1;

	if (!json_object_object_get_ex(obj, "object", &o) ||
	    !json_object_is_type(o, json_type_object)) {
		TSError("[watcher] JSON object has no object");
		json_object_put(obj);
		return;
	}

	if (!json_object_object_get_ex(o, "kind", &kind) ||
	    !json_object_is_type(kind, json_type_string)) {
		TSError("[watcher] JSON object has no kind");
		json_object_put(obj);
		return;
	}
	
	skind = json_object_get_string(kind);

	if (!json_object_object_get_ex(o, "metadata", &metadata) ||
	    !json_object_is_type(metadata, json_type_object)) {
		TSError("fetcher_process_item: resource has no metadata?");
		return;
	}

	if (!json_object_object_get_ex(metadata, "namespace", &namespace) ||
	    !json_object_is_type(namespace, json_type_string)) {
		TSError("fetcher_process_item: resource has no namespace?");
		return;
	}

	if (!json_object_object_get_ex(metadata, "name", &name) ||
	    !json_object_is_type(name, json_type_string)) {
		TSError("fetcher_process_item: resource has no name?");
		return;
	}

	sname = json_object_get_string(name);

	TSDebug("watcher", "fetcher_watch_line: change %s from %s",
		skind, json_object_get_string(namespace));

	pthread_rwlock_wrlock(&fe->watcher->wt_cluster->cs_lock);
	ns = cluster_get_namespace(fe->watcher->wt_cluster,
				   json_object_get_string(namespace));

	/* What sort of object is this? */

	if (strcmp(skind, "Ingress") == 0) {
		if (deleted)
			namespace_del_ingress(ns, sname);
		else {
		ingress_t	*ing;
			if ((ing = ingress_make(o)) != NULL)
				namespace_put_ingress(ns, ing);
			else
				TSError("fetcher_process_item: could not parse Ingress");
		}
		fe->changed = 1;
	} else if (strcmp(skind, "Service") == 0) {
		if (deleted)
			namespace_del_service(ns, sname);
		else {
		service_t	*svc;
			if ((svc = service_make(o)) != NULL)
				namespace_put_service(ns, svc);
			else
				TSError("fetcher_process_item: could not parse Service");
		}
		fe->changed = 1;
	} else if (strcmp(skind, "Secret") == 0) {
		if (deleted)
			namespace_del_secret(ns, sname);
		else {
		secret_t	*sec;
			if ((sec = secret_make(o)) != NULL)
				namespace_put_secret(ns, sec);
			else
				TSError("fetcher_process_item: could not parse Secret");
		}
		fe->changed = 1;
	} else if (strcmp(skind, "Endpoints") == 0) {
		if (deleted) {
			namespace_del_endpoints(ns, sname);
			fe->changed = 1;
		} else {
		endpoints_t	*eps;

			/* 
			 * Kubernetes sends frequent updates (once per second)
			 * for the 'kubernetes' and 'kube-scheduler' endpoints;
			 * to avoid wasting large amounts of CPU rebuilding the
			 * map every time, ignore the update if the new
			 * endpoints is identical to the existing one.
			 */
			if ((eps = endpoints_make(o)) == NULL)
				TSError("fetcher_process_item: could not parse Endpoints");
			else {
			endpoints_t	*old;
				if ((old = namespace_get_endpoints(ns, sname)) == NULL ||
				    !endpoints_equal(eps, old)) {
					namespace_put_endpoints(ns, eps);
					fe->changed = 1;
				} else
					endpoints_free(eps);
			}
		}
	} else {
		TSError("fetch_process_item: unknown resource type %s?", skind);
	}

	pthread_rwlock_unlock(&fe->watcher->wt_cluster->cs_lock);

	json_object_put(obj);
}

static size_t
fe_watch_read(char *data, size_t sz, size_t n, void *udata)
{
struct fetcher_ctx	*fe = udata;
size_t			 nread = sz * n;
char			*s;
char			*bufptr, *bufend;

	if (nread == 0)
		return 0;

	/* Copy the new data into our buffer */
	fe->buf = realloc(fe->buf, fe->buflen + nread);
	bcopy(data, fe->buf + fe->buflen, nread);
	fe->buflen += nread;

	bufptr = fe->buf;
	bufend = bufptr + fe->buflen;

	/* Process any complete lines we've read */
	while ((s = memchr(bufptr, '\n', (bufend - bufptr))) != NULL) {
		*s = '\0';
		fe_watch_line(fe, bufptr);
		bufptr = s + 1;
	}

	memmove(fe->buf, bufptr, (bufend - bufptr));
	fe->buflen = (bufend - bufptr);

	return nread;
}

int
fetcher_make(watcher_t *wt, struct fetcher_ctx *fe, struct resource *resource)
{
size_t	urllen;

	bzero(fe, sizeof(*fe));
	fe->resource = resource;
	fe->watcher = wt;
	fe->curl = watcher_make_curl(wt, fe->errbuf, &fe->hdrs, fe_read, fe);
	if (fe->curl == NULL)
		return -1;

	urllen = strlen(wt->wt_config->co_server) + strlen(resource->url) + 1;
	fe->url = malloc(urllen);
	snprintf(fe->url, urllen, "%s%s", wt->wt_config->co_server,
		 resource->url);
	curl_easy_setopt(fe->curl, CURLOPT_URL, fe->url);
	return 0;
}

int
fetcher_watch_make(watcher_t *wt, struct fetcher_ctx *fe,
		   struct resource *resource)
{
size_t	urllen;

	bzero(fe, sizeof(*fe));
	fe->resource = resource;
	fe->watcher = wt;
	fe->curl = watcher_make_curl(wt, fe->errbuf, &fe->hdrs,
				     fe_watch_read, fe);
	if (fe->curl == NULL)
		return -1;

	urllen = strlen(wt->wt_config->co_server) + strlen(resource->url) + 
		+ strlen(resource->version) +
		sizeof("?watch=true&resourceVersion=");
	fe->url = malloc(urllen);
	snprintf(fe->url, urllen, "%s%s?watch=true&resourceVersion=%s",
		 wt->wt_config->co_server, resource->url, resource->version);
	curl_easy_setopt(fe->curl, CURLOPT_URL, fe->url);
	return 0;
}

void
fetcher_process_item(struct fetcher_ctx *fe, cluster_t *cluster,
		     const char *kind, json_object *item)
{
json_object	*metadata, *namespace;
namespace_t	*ns;

	TSDebug("watcher", "fetcher_process_item: running");

	if (!json_object_object_get_ex(item, "metadata", &metadata) ||
	    !json_object_is_type(metadata, json_type_object)) {
		TSError("fetcher_process_item: resource has no metadata?");
		return;
	}

	if (!json_object_object_get_ex(metadata, "namespace", &namespace) ||
	    !json_object_is_type(namespace, json_type_string)) {
		TSError("fetcher_process_item: resource has no namespace?");
		return;
	}

	TSDebug("watcher", "fetcher_process_item: adding %s from %s",
		kind, json_object_get_string(namespace));

	ns = cluster_get_namespace(cluster,
				   json_object_get_string(namespace));

	/* What sort of object is this? */
	
	if (strcmp(kind, "IngressList") == 0) {
	ingress_t	*ing;
		if ((ing = ingress_make(item)) == NULL) {
			TSError("fetcher_process_item: could not parse Ingress");
			return;
		}

		namespace_put_ingress(ns, ing);
	} else if (strcmp(kind, "ServiceList") == 0) {
	service_t	*svc;
		if ((svc = service_make(item)) == NULL)
			TSError("fetcher_process_item: could not parse Service");
		else
			namespace_put_service(ns, svc);
	} else if (strcmp(kind, "SecretList") == 0) {
	secret_t	*sec;
		if ((sec = secret_make(item)) == NULL)
			TSError("fetcher_process_item: could not parse Secret");
		else
			namespace_put_secret(ns, sec);
	} else if (strcmp(kind, "EndpointsList") == 0) {
	endpoints_t	*eps;
		if ((eps = endpoints_make(item)) == NULL)
			TSError("fetcher_process_item: could not parse Endpoints");
		else
			namespace_put_endpoints(ns, eps);
	} else {
		TSError("fetch_process_item: unknown resource type %s?", kind);
		return;
	}
}

void
fetcher_process(struct fetcher_ctx *fe, cluster_t *cluster)
{
json_object		*obj = NULL, *items = NULL, *metadata, *rversion, *kind;
const char		*skind;

	TSDebug("watcher", "fetcher_process: running; %d in buf",
		(int) fe->buflen);

	if (!fe->buf)
		return;

	/*
	 * json-c requires a nul-terminated buffer.  We allocate an additional
	 * byte in fe_read() so we can terminate it here.
	 */
	fe->buf[fe->buflen] = '\0';
	if ((obj = json_tokener_parse(fe->buf)) == NULL) {
		TSError("fetcher_process: could not parse JSON: [%.*s]",
			(int) (fe->buflen > 128 ? 128 : fe->buflen), fe->buf);
		goto cleanup;
	}

	if (!json_object_object_get_ex(obj, "items", &items) ||
	    !json_object_is_type(items, json_type_array)) {
		TSError("fetcher_process: no items in API server response");
		goto cleanup;
	}

	if (!json_object_object_get_ex(obj, "metadata", &metadata) ||
	    !json_object_is_type(metadata, json_type_object)) {
		TSError("fetcher_process: response has no metadata?");
		goto cleanup;
	}

	if (!json_object_object_get_ex(metadata, "resourceVersion", &rversion) ||
	    !json_object_is_type(rversion, json_type_string)) {
		TSError("fetcher_process: response has no resourseVersion?");
		goto cleanup;
	}
	free(fe->resource->version);
	fe->resource->version = strdup(json_object_get_string(rversion));

	if (!json_object_object_get_ex(obj, "kind", &kind) ||
	    !json_object_is_type(kind, json_type_string)) {
		TSError("fetcher_process: response has no kind?");
		goto cleanup;
	}

	skind = json_object_get_string(kind);

	for (int i = 0, end = json_object_array_length(items); i != end; ++i) {
	json_object	*item = json_object_array_get_idx(items, i);

		fetcher_process_item(fe, cluster, skind, item);
	}

cleanup:
	if (obj)
		json_object_put(obj);
}

void
fetcher_free(struct fetcher_ctx *fe)
{
	if (fe->curl)
		curl_easy_cleanup(fe->curl);
	curl_slist_free_all(fe->hdrs);
	free(fe->buf);
	free(fe->url);
}

int
fetcher_get_all(watcher_t *wt)
{
struct fetcher_ctx	 fetchers[NRESOURCES];
int			 fail = 0, running;
CURLM			*multi = NULL;
CURLMsg			*msg;
int			 n;
cluster_t		*cluster = NULL, *newcluster = NULL;
hash_t			 tmphash;

	bzero(fetchers, sizeof(fetchers));

	if ((multi = curl_multi_init()) == NULL) {
		TSError("fetcher_get_all: curl_multi_init() failed");
		fail++;
		goto cleanup;
	}

	for (size_t i = 0; i < NRESOURCES; ++i) {
		if (fetcher_make(wt, &fetchers[i], &resources[i]) != 0) {
			fail++;
			goto cleanup;
		}

		curl_multi_add_handle(multi, fetchers[i].curl);
	}

	TSDebug("watcher", "fetcher_get_all: starting fetch");
	for (;;) {
	CURLMcode	mc;
	int		nfds;
	long		timeout;

		//TSDebug("watcher", "fetcher_get_all: curl_multi_perform");
		mc = curl_multi_perform(multi, &running);
		if (mc != CURLM_OK) {
			TSError("fetcher_get_all: curl_multi_perform failed: %d",
				mc);
			fail++;
			goto cleanup;
		}

		if (!running)
			break;

		curl_multi_timeout(multi, &timeout);
		//TSDebug("watcher", "fetcher_get_all: timeout=%d running=%d",
		//	(int) timeout, running);
		if (timeout == 0)
			continue;
		if (timeout == -1)
			timeout = 1000;

		//TSDebug("watcher", "fetcher_get_all: curl_multi_wait");
		mc = curl_multi_wait(multi, NULL, 0, timeout, &nfds);
		if (mc != CURLM_OK) {
			TSError("fetcher_get_all: curl_multi_wait failed: %d", mc);
			fail++;
			goto cleanup;
		}
	}
	TSDebug("watcher", "fetch_get_all: done fetch");

	newcluster = cluster_make();
	cluster = wt->wt_cluster;

	while ((msg = curl_multi_info_read(multi, &n)) != NULL) {
	struct fetcher_ctx *fe = NULL;
		if (msg->msg != CURLMSG_DONE)
			continue;

		for (size_t i = 0; i < NRESOURCES; i++) {
			if (fetchers[i].curl != msg->easy_handle)
				continue;
			fe = &fetchers[i];
			break;
		}
		assert(fe);

		TSDebug("watcher", "fetcher_get_all: fetch for "
			"%s finished: status=%d", fe->url, msg->data.result);

		if (msg->data.result != CURLE_OK) {
			TSDebug("watcher", "fetcher_get_all: failed: %s",
				fe->errbuf);
			cluster_free(newcluster);
			fail++;
			goto cleanup;
		}

		fetcher_process(fe, newcluster);
	}

	pthread_rwlock_wrlock(&cluster->cs_lock);
	tmphash = cluster->cs_namespaces;
	cluster->cs_namespaces = newcluster->cs_namespaces;
	newcluster->cs_namespaces = tmphash;
	pthread_rwlock_unlock(&cluster->cs_lock);

	cluster_free(newcluster);

	if (cluster->cs_callback)
		cluster->cs_callback(cluster, cluster->cs_callbackdata);

cleanup:
	for (size_t i = 0; i < NRESOURCES; ++i) {
		if (fetchers[i].curl && multi) {
			if (multi)
				curl_multi_remove_handle(multi, fetchers[i].curl);
		}
		fetcher_free(&fetchers[i]);
	}

	if (multi)
		curl_multi_cleanup(multi);

	return fail ? -1 : 0;
}

int
fetcher_watch(watcher_t *wt)
{
struct fetcher_ctx	 fetchers[NRESOURCES];
int			 fail = 0, running;
CURLM			*multi = NULL;
time_t			 deadline;

	/* When to stop watching and return for a resync */
	deadline = time(NULL) + RESYNC_INTERVAL;

	bzero(fetchers, sizeof(fetchers));

	if ((multi = curl_multi_init()) == NULL) {
		TSError("fetcher_watch: curl_multi_init() failed");
		fail++;
		goto cleanup;
	}

	for (size_t i = 0; i < NRESOURCES; ++i) {
		if (fetcher_watch_make(wt, &fetchers[i], &resources[i]) != 0) {
			fail++;
			goto cleanup;
		}

		curl_multi_add_handle(multi, fetchers[i].curl);
	}

	TSDebug("watcher", "fetcher_watch: starting watch");
	for (;;) {
	CURLMcode	mc;
	int		nfds;
	long		timeout;
	int		anychanged = 0;

		//TSDebug("watcher", "fetcher_get_all: curl_multi_perform");
		mc = curl_multi_perform(multi, &running);
		if (mc != CURLM_OK) {
			TSError("fetcher_watch: curl_multi_perform failed: %d",
				mc);
			fail++;
			goto cleanup;
		}

		/* If any watch finishes, we want to return for a resync */
		if (running != NRESOURCES) {
			TSError("watcher: a watch finished early");
			fail++;
			break;
		}

		curl_multi_timeout(multi, &timeout);
		if (timeout == 0)
			continue;
		if (timeout == -1 || timeout > 1000)
			timeout = 1000;

		mc = curl_multi_wait(multi, NULL, 0, timeout, &nfds);
		if (mc != CURLM_OK) {
			TSError("fetcher_get_all: curl_multi_wait failed: %d", mc);
			fail++;
			goto cleanup;
		}

		if (time(NULL) >= deadline)
			break;

		for (size_t i = 0; i < NRESOURCES; ++i) {
			if (fetchers[i].changed) {
				anychanged++;
				fetchers[i].changed = 0;
			}
		}

		if (anychanged && wt->wt_cluster->cs_callback)
			wt->wt_cluster->cs_callback(
				wt->wt_cluster,
				wt->wt_cluster->cs_callbackdata);
	}
	TSDebug("watcher", "fetch_watch: done watch");

cleanup:
	for (size_t i = 0; i < NRESOURCES; ++i) {
		if (fetchers[i].curl && multi) {
			if (multi)
				curl_multi_remove_handle(multi, fetchers[i].curl);
		}
		fetcher_free(&fetchers[i]);
	}

	if (multi)
		curl_multi_cleanup(multi);

	return fail ? -1 : 0;
}

void *
watcher_thread(void *data)
{
watcher_t	*wt = data;

	for (;;) {
		/* First, do a full fetch of resources for each type. */
		TSDebug("watcher", "watcher_thread: starting resync");

		if (fetcher_get_all(wt) == -1) {
			sleep(10);
			continue;
		}

		/* Then watch for resource changes until the resync timeout */
		TSDebug("watcher", "watcher_thread: starting watch");
		fetcher_watch(wt);
	}

	return NULL;
}

int
watcher_run(watcher_t *wt)
{
	TSDebug("watcher", "[%s]: starting", wt->wt_config->co_server);
	TSThreadCreate(watcher_thread, wt);
	return 0;
}

void
watcher_set_callback(watcher_t *wt, cluster_callback_t cb, void *cbdata)
{
	wt->wt_cluster->cs_callback = cb;
	wt->wt_cluster->cs_callbackdata = cbdata;
}

void
watcher_free(watcher_t *wt)
{
	free(wt);
}
