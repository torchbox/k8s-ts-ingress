/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * plugin.c: provide TS plugin entrypoints, create watchers for the resources
 * we need, and handle keeping the cluster state up to date.
 */

#include	<errno.h>
#include	<string.h>

#include	<json.h>
#include	<ts/ts.h>

#include	"hash.h"
#include	"watcher.h"
#include	"config.h"
#include	"plugin.h"

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
 * Store state as a global, since a continutation can't have data without a
 * mutex.
 */
struct state *state;

/*
 * Initialise plugin, load configuration and start our watchers.
 */
void
TSPluginInit(int argc, const char **argv)
{
TSPluginRegistrationInfo	 info;
k8s_config_t			*conf;
size_t				 i;
struct {
	const char *resource;
	watcher_callback_t callback;
} watchers[] = {
	{ "/apis/extensions/v1beta1/ingresses",	ingress_cb },
	{ "/api/v1/secrets",			secret_cb },
	{ "/api/v1/services",			service_cb },
	{ "/api/v1/endpoints",			endpoints_cb },
};

	SSL_library_init();
	SSL_load_error_strings();

	if (argc < 2) {
		TSError("[kubernetes] configuration file not specified");
		return;
	}

	if ((conf = k8s_config_load(argv[1])) == NULL) {
		TSError("[kubernetes] failed to load configuration");
		return;
	}

	if ((state = calloc(1, sizeof(*state))) == NULL) {
		TSError("[kubernetes] Cannot create tls_state: %s",
			strerror(errno));
		return;
	}

	state->map_lock = TSMutexCreate();
	state->cluster_lock = TSMutexCreate();
	state->cluster = cluster_make();

	/*
	 * Create watchers.
	 */
	for (i = 0; i < sizeof(watchers) / sizeof(*watchers); i++) {
	watcher_t	wt;
		wt = watcher_create(conf, watchers[i].resource);

		if (wt == NULL) {
			TSError("[kubernetes] cannot create watcher for %s: %s",
				watchers[i].resource, strerror(errno));
			return;
		}

		TSDebug("kubernetes", "created watcher for %s",
			watchers[i].resource);
		watcher_set_callback(wt, watchers[i].callback, NULL);
		watcher_run(wt, 0);
	}

	/*
	 * Create continuation to rebuild the maps when something changes.
	 */
	if ((state->rebuild_cont = TSContCreate(handle_rebuild, TSMutexCreate())) == NULL) {
		TSError("[kubernetes] Failed to create continuation.");
		return;
	}

	TSContDataSet(state->rebuild_cont, state);

	/*
	 * Create SNI hook to associate Kubernetes SSL_CTXs with incoming
	 * connections.
	 */
	state->tls_cont = TSContCreate(handle_tls, NULL);
	TSHttpHookAdd(TS_SSL_SNI_HOOK, state->tls_cont);

	/*
	 * Create remap hook to map incoming requests to pods.
	 */
	state->remap_cont = TSContCreate(handle_remap, NULL);
	TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, state->remap_cont);

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
ingress_t	*ing;
namespace_t	*ns;

	if ((ing = ingress_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Ingress object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes", "something happened with an ingress: %s/%s",
		ing->in_namespace, ing->in_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, ing->in_namespace);
	if (ev == WT_DELETED)
		namespace_del_ingress(ns, ing->in_name);
	else
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
secret_t		*secret;
namespace_t		*ns;

	if ((secret = secret_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Secret object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes", "something happened with a secret: %s/%s",
		secret->se_namespace, secret->se_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, secret->se_namespace);
	if (ev == WT_DELETED)
		namespace_del_secret(ns, secret->se_name);
	else
		namespace_put_secret(ns, secret);

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}

	TSMutexUnlock(state->cluster_lock);
}

static void
endpoints_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
endpoints_t		*endpoints;
namespace_t		*ns;

	if ((endpoints = endpoints_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Endpoints object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes", "something happened with a endpoints: %s/%s",
		endpoints->ep_namespace, endpoints->ep_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, endpoints->ep_namespace);
	if (ev == WT_DELETED)
		namespace_del_endpoints(ns, endpoints->ep_name);
	else
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
service_t		*service;
namespace_t		*ns;

	if ((service = service_make(obj)) == NULL) {
		TSError("[kubernetes] Could not parse Service object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes", "something happened with a service: %s/%s",
		service->sv_namespace, service->sv_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, service->sv_namespace);
	if (ev == WT_DELETED)
		namespace_del_service(ns, service->sv_name);
	else
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
	switch (evt) {
	case TS_EVENT_TIMEOUT:
		TSDebug("kubernetes", "timeout event; rebuilding");
		rebuild_maps();
		return TS_SUCCESS;

	default:
		TSDebug("kubernetes", "unknown event %d received", (int) evt);
		return TS_SUCCESS;
	}

	return TS_SUCCESS;
}
