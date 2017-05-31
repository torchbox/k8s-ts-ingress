/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

/*
 * plugin.c: provide TS plugin entrypoints, create watchers for the resources
 * we need, and handle keeping the cluster state up to date.
 */

#include	<errno.h>
#include	<string.h>
#include	<unistd.h>

#include	<json.h>
#include	<curl/curl.h>
#include	<ts/ts.h>

#include	"hash.h"
#include	"watcher.h"
#include	"config.h"
#include	"plugin.h"
#include	"autoconf.h"

char *via_name;
int via_name_len;
char myhostname[HOST_NAME_MAX + 1];

/*
 * Watcher callbacks; called when the Kubernetes cluster state changes.
 */
static void ingress_cb(watcher_t, wt_event_type_t, json_object *, void *);
static void service_cb(watcher_t, wt_event_type_t, json_object *, void *);
static void secret_cb(watcher_t, wt_event_type_t, json_object *, void *);
static void endpoints_cb(watcher_t, wt_event_type_t, json_object *, void *);

/*
 * Rebuild the map when cluster state changes.
 */
static int handle_rebuild(TSCont, TSEvent, void *);

/*
 * Initialise plugin, load configuration and start our watchers.
 */
void
TSPluginInit(int argc, const char **argv)
{
TSPluginRegistrationInfo	 info;
size_t				 i;
struct state			*state;
struct {
	const char *resource;
	watcher_callback_t callback;
} watchers[] = {
	{ "/apis/extensions/v1beta1/ingresses",	ingress_cb },
	{ "/api/v1/secrets",			secret_cb },
	{ "/api/v1/services",			service_cb },
	{ "/api/v1/endpoints",			endpoints_cb },
};

	via_name_len = snprintf(NULL, 0, "ATS/%s Ingress/%s",
				TSTrafficServerVersionGet(), PACKAGE_VERSION);
	via_name = malloc(via_name_len + 1);
	via_name_len = snprintf(via_name, via_name_len + 1, "ATS/%s Ingress/%s",
				TSTrafficServerVersionGet(), PACKAGE_VERSION);

	if (gethostname(myhostname, sizeof(myhostname)) == -1)
		strcpy(myhostname, "unknown");

	SSL_library_init();
	SSL_load_error_strings();

	curl_global_init(CURL_GLOBAL_ALL);

	if ((state = calloc(1, sizeof(*state))) == NULL) {
		TSError("[kubernetes] cannot create state: %s",
			strerror(errno));
		return;
	}

	if (argc >= 2)
		state->config = k8s_config_load(argv[1]);
	else
		state->config = k8s_config_load(NULL);

	if (state->config == NULL) {
		TSError("[kubernetes] failed to load configuration");
		return;
	}

	state->cluster_lock = TSMutexCreate();
	state->cluster = cluster_make();
	state->cfg_slot = TSConfigSet(0, NULL, (TSConfigDestroyFunc) hash_free);

	/*
	 * Create continuation to rebuild the maps when something changes.
	 */
	if ((state->rebuild_cont = TSContCreate(handle_rebuild, TSMutexCreate())) == NULL) {
		TSError("[kubernetes] Failed to create continuation.");
		return;
	}

	TSContDataSet(state->rebuild_cont, state);
	/*
	 * Create watchers.
	 */
	for (i = 0; i < sizeof(watchers) / sizeof(*watchers); i++) {
	watcher_t	wt;
		wt = watcher_create(state->config, watchers[i].resource);

		if (wt == NULL) {
			TSError("[kubernetes] cannot create watcher for %s: %s",
				watchers[i].resource, strerror(errno));
			return;
		}

		TSDebug("kubernetes", "created watcher for %s",
			watchers[i].resource);
		watcher_set_callback(wt, watchers[i].callback, state);
		watcher_run(wt, 0);
	}

	/*
	 * Create SNI hook to associate Kubernetes SSL_CTXs with incoming
	 * connections.
	 */
	TSDebug("kubernetes", "co_tls=%d", state->config->co_tls);
	if (state->config->co_tls) {
		state->tls_cont = TSContCreate(handle_tls, NULL);
		TSContDataSet(state->tls_cont, state);
#ifdef TS_SSL_CERT_HOOK
		TSHttpHookAdd(TS_SSL_CERT_HOOK, state->tls_cont);
#else
		TSHttpHookAdd(TS_SSL_SNI_HOOK, state->tls_cont);
#endif
	}

	/*
	 * Create remap hook to map incoming requests to pods.
	 */
	if (state->config->co_remap) {
		state->remap_cont = TSContCreate(handle_remap, NULL);
		TSContDataSet(state->remap_cont, state);
		TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, state->remap_cont);
	}

	/*
	 * Register ourselves.
	 */
	info.plugin_name = "Kubernetes Ingress plugin";
	info.vendor_name = "Torchbox, Ltd.";
	info.support_email = "sysadmin@torchbox.com";
	if (TSPluginRegister(&info) != TS_SUCCESS) {
		TSError("[kubernetes] Plugin registration failed.");
		return;
	}
}

/*
 * Watcher callbacks.  All of these lock the entire cluster state while running;
 * this isn't a problem since cluster changes are fairly infrequent (at most
 * a few per second) and the cluster lock doesn't interfere with request
 * serving.
 */

static void
ingress_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
ingress_t	*ing, *old;
namespace_t	*ns;
struct state	*state = data;

	if ((ing = ingress_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Ingress object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes", "something happened with an ingress: %s/%s",
		ing->in_namespace, ing->in_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, ing->in_namespace);
	if (ev == WT_DELETED) {
		if ((old = namespace_del_ingress(ns, ing->in_name)) != NULL)
			ingress_free(old);
		ingress_free(ing);
	} else
		namespace_put_ingress(ns, ing);

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}

	TSMutexUnlock(state->cluster_lock);
}

static void
secret_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
secret_t		*secret, *old;
namespace_t		*ns;
struct state	*state = data;

	if ((secret = secret_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Secret object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes", "something happened with a secret: %s/%s",
		secret->se_namespace, secret->se_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, secret->se_namespace);
	if (ev == WT_DELETED) {
		if ((old = namespace_del_secret(ns, secret->se_name)) != NULL)
			secret_free(old);
		secret_free(secret);
	} else
		namespace_put_secret(ns, secret);

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}

	TSMutexUnlock(state->cluster_lock);
}

/*
 * Kubernetes updates all endpoints objects every few seconds; to avoid
 * constantly rebuilding the route map, only update if the new Endpoints
 * is different from the last one.
 */

static int
endpoints_equal(endpoints_t *a, endpoints_t *b)
{
size_t			 i, j;
struct hash_iter_state	 isa, isb;

	if (strcmp(a->ep_name, b->ep_name))
		return 0;
	if (strcmp(a->ep_namespace, b->ep_namespace))
		return 0;
	if (a->ep_nsubsets != b->ep_nsubsets)
		return 0;

	for (i = 0; i < a->ep_nsubsets; i++) {
	endpoints_subset_t	*as = &a->ep_subsets[i],
				*bs = &b->ep_subsets[i];

		if (as->es_naddrs != bs->es_naddrs)
			return 0;

		for (j = 0; j < as->es_naddrs; j++) {
		endpoints_address_t	*aa = &as->es_addrs[j],
					*ba = &bs->es_addrs[j];

			if (aa->ea_ip == NULL) {
				if (ba->ea_ip != NULL)
					return 0;
			} else if (ba->ea_ip == NULL) {
				return 0;
			} else {
				if (strcmp(aa->ea_ip, ba->ea_ip))
					return 0;
			}

			if (aa->ea_nodename == NULL) {
				if (ba->ea_nodename != NULL)
					return 0;
			} else if (ba->ea_nodename == NULL) {
				return 0;
			} else {
				if (strcmp(aa->ea_nodename, ba->ea_nodename))
					return 0;
			}
		}

		bzero(&isa, sizeof(isa));
		bzero(&isb, sizeof(isb));
		for (;;) {
		int			 ra, rb;
		const char		*ka, *kb;
		endpoints_port_t	*pa, *pb;

			ra = hash_iterate(as->es_ports, &isa, &ka, (void **)&pa);
			rb = hash_iterate(bs->es_ports, &isb, &kb, (void **)&pb);
			if (ra != rb)
				return 0;

			if (!ra)
				break;

			if (strcmp(ka, kb))
				return 0;
			if (strcmp(pa->et_name, pb->et_name))
				return 0;
			if (strcmp(pa->et_protocol, pb->et_protocol))
				return 0;
			if (pa->et_port != pb->et_port)
				return 0;
		}
	}

	return 1;
}

static void
endpoints_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
endpoints_t		*endpoints, *eps2, *old;
namespace_t		*ns;
struct state		*state = data;

	if ((endpoints = endpoints_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Endpoints object: %s",
			json_object_get_string(obj));
		return;
	}

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, endpoints->ep_namespace);

	if (ev == WT_UPDATED) {
		if ((eps2 = namespace_get_endpoints(ns, endpoints->ep_name)) != NULL) {
			if (endpoints_equal(endpoints, eps2)) {
				endpoints_free(endpoints);
				TSMutexUnlock(state->cluster_lock);
				return;
			}
		}
	}

	TSDebug("kubernetes", "something happened with a endpoints: %s/%s",
		endpoints->ep_namespace, endpoints->ep_name);

	if (ev == WT_DELETED) {
		if ((old = namespace_del_endpoints(ns, endpoints->ep_name)) != NULL)
			endpoints_free(old);
		endpoints_free(endpoints);
	} else
		namespace_put_endpoints(ns, endpoints);

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}

	TSMutexUnlock(state->cluster_lock);
}

static void
service_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
service_t		*service, *old;
namespace_t		*ns;
struct state		*state = data;

	if ((service = service_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Service object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes", "something happened with a service: %s/%s",
		service->sv_namespace, service->sv_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, service->sv_namespace);
	if (ev == WT_DELETED) {
		if ((old = namespace_del_service(ns, service->sv_name)) != NULL)
			service_free(old);
		service_free(service);
	} else
		namespace_put_service(ns, service);

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}

	TSMutexUnlock(state->cluster_lock);
}

/*
 * Rebuild continuation.  This is called after a delay whenever the cluster
 * state changes.
 */
static int
handle_rebuild(TSCont contn, TSEvent evt, void *edata)
{
struct state	*state = TSContDataGet(contn);

	switch (evt) {
	case TS_EVENT_TIMEOUT:
		TSDebug("kubernetes", "timeout event; rebuilding");
		rebuild_maps(state);
		return TS_SUCCESS;

	default:
		TSDebug("kubernetes", "unknown event %d received", (int) evt);
		return TS_SUCCESS;
	}

	return TS_SUCCESS;
}
