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

#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<getopt.h>

#include	<ts/ts.h>
#include	<ts/apidefs.h>
#include	<ts/remap.h>

#include	<openssl/ssl.h>

#include	<json.h>

#include	"hash.h"
#include	"api.h"
#include	"watcher.h"
#include	"config.h"
#include	"tls.h"

struct tls_state {
	TSMutex		 cluster_lock;
	cluster_t	*cluster;
	watcher_t	 ingress_watcher;
	watcher_t	 secret_watcher;
	int		 changed;

	TSMutex		 map_lock;
	hash_t		 map;

	TSCont		 rebuild_cont;
	TSCont		 map_cont;
};

struct tls_state *state;

struct rebuild_ctx {
	hash_t		 map;
	namespace_t	*ns;
};

void
rebuild_ingress_tls(struct rebuild_ctx *ctx, ingress_t *ing,
		    ingress_tls_t *itls)
{
secret_t	*secret;
size_t		 i;

	TSDebug("kubernetes_tls", "    secret %s (%d hosts):",
		itls->it_secret_name, (int) itls->it_nhosts);

	if ((secret = namespace_get_secret(ctx->ns, itls->it_secret_name)) == NULL) {
		TSDebug("kubernete_tls", "Could not find secret [%s]",
			itls->it_secret_name);
		return;
	}

	for (i = 0; i < itls->it_nhosts; i++) {
	SSL_CTX		*ssl_ctx;
	const char	*host = itls->it_hosts[i];

		if (hash_get(ctx->map, host)) {
			TSDebug("kubernetes_tls", "      %s: already present", host);
			continue;
		}

		if ((ssl_ctx = secret_make_ssl_ctx(secret)) == NULL) {
			TSDebug("kubernetes_tls", "      %s: can't make ctx", host);
			continue;
		}

		hash_set(ctx->map, host, ssl_ctx);
		TSDebug("kubernetes_tls", "      %s: added with CTX[%p]",
			host, ssl_ctx);
	}
}

void
rebuild_ingress(hash_t hs, const char *ingname, void *value, void *data)
{
struct rebuild_ctx	*ctx = data;
ingress_t		*ing = value;
size_t			 i;

	TSDebug("kubernetes_tls", "  ingress %s:", ingname);
	for (i = 0; i < ing->in_ntls; i++)
		rebuild_ingress_tls(ctx, ing, &ing->in_tls[i]);
}

void
rebuild_namespace(hash_t hs, const char *nsname, void *value, void *data)
{
struct rebuild_ctx	*ctx = data;
namespace_t		*ns = value;

	TSDebug("kubernetes_tls", "namespace %s:", nsname);
	ctx->ns = ns;
	hash_foreach(ns->ns_ingresses, rebuild_ingress, ctx);
}

void
rebuild_tls_map(struct tls_state *state)
{
hash_t			old_map;
struct rebuild_ctx	ctx;

	TSMutexLock(state->cluster_lock);
	if (!state->changed) {
		TSDebug("kubernetes_tls", "rebuild_tls_map: no changes");
		TSMutexUnlock(state->cluster_lock);
		return;
	}

	TSDebug("kubernetes_tls", "rebuild_tls_map: running");
	ctx.map = hash_new(127, (hash_free_fn) SSL_CTX_free);
	hash_foreach(state->cluster->cs_namespaces, rebuild_namespace, &ctx);
	state->changed = 0;

	TSMutexLock(state->map_lock);
	old_map = state->map;
	state->map = ctx.map;
	TSMutexUnlock(state->map_lock);

	TSMutexUnlock(state->cluster_lock);

	if (old_map)
		hash_free(old_map);
}

int
handle_map(TSCont contn, TSEvent evt, void *edata)
{
TSVConn			 ssl_vc = edata;
SSL			*ssl = (SSL *)TSVConnSSLConnectionGet(ssl_vc);
const char		*host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
SSL_CTX			*ctx;

	TSDebug("kubernetes_tls", "doing SNI map for [%s]", host);

	TSMutexLock(state->map_lock);
	if ((ctx = hash_get(state->map, host)) != NULL) {
		TSDebug("kubernetes_tls", "[%s]: found ctx", host);
		SSL_set_SSL_CTX(ssl, ctx);
		TSVConnReenable(ssl_vc);
	} else {
		TSDebug("kubernetes_tls", "[%s]: no ctx", host);
	}
	TSMutexUnlock(state->map_lock);

	return TS_SUCCESS;
}

int
handle_rebuild(TSCont contn, TSEvent evt, void *edata)
{
struct tls_state	*state = TSContDataGet(contn);

	switch (evt) {
	case TS_EVENT_TIMEOUT:
		TSDebug("kubernetes_tls", "timeout event");
		rebuild_tls_map(state);
		return TS_SUCCESS;

	default:
		TSDebug("kubernetes_tls", "unknown event %d received", (int) evt);
		return TS_SUCCESS;
	}

	return TS_SUCCESS;
}

void
ingress_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
ingress_t		*ing;
namespace_t		*ns;
struct tls_state	*state = data;

	if ((ing = ingress_make(obj)) == NULL) {
		TSError("[kubernetes_tls] Could not parse Ingress object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes_tls", "something happened with an ingress: %s/%s",
		ing->in_namespace, ing->in_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, ing->in_namespace);
	if (ev == WT_DELETED) {
		namespace_del_ingress(ns, ing->in_name);
	} else {
		namespace_put_ingress(ns, ing);
	}

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}
	TSMutexUnlock(state->cluster_lock);
}

void
secret_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
secret_t		*secret;
namespace_t		*ns;
struct tls_state	*state = data;

	if ((secret = secret_make(obj)) == NULL) {
		TSError("[kubernetes_tls] Could not parse Secret object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes_tls", "something happened with a secret: %s/%s",
		secret->se_namespace, secret->se_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, secret->se_namespace);
	if (ev == WT_DELETED) {
		namespace_del_secret(ns, secret->se_name);
	} else {
		namespace_put_secret(ns, secret);
	}

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}
	TSMutexUnlock(state->cluster_lock);
}

void
TSPluginInit(int argc, const char **argv)
{
TSPluginRegistrationInfo	 info;
k8s_config_t			*conf;

	SSL_library_init();
	SSL_load_error_strings();

	if (argc < 2) {
		TSError("[kubernetes_tls] configuration file not specified");
		return;
	}

	if ((conf = k8s_config_load(argv[1])) == NULL) {
		TSError("[kubernetes_tls] failed to load configuration");
		return;
	}

	if ((state = calloc(1, sizeof(*state))) == NULL) {
		TSError("[kubernetes_tls] Cannot create tls_state: %s",
			strerror(errno));
		return;
	}

	state->map_lock = TSMutexCreate();
	state->cluster_lock = TSMutexCreate();
	state->cluster = cluster_make();

	/*
	 * Create watcher for Ingresses.
	 */
	state->ingress_watcher = watcher_create(conf,
					 "/apis/extensions/v1beta1/ingresses");
	if (state->ingress_watcher == NULL) {
		TSError("[kubernetes_tls] Cannot create Ingress watcher: %s",
			strerror(errno));
		free(state);
		return;
	}

	watcher_set_callback(state->ingress_watcher, ingress_cb, state);
	watcher_run(state->ingress_watcher, 0);

	/*
	 * Create watcher for Secrets
	 */
	state->secret_watcher = watcher_create(conf, "/api/v1/secrets");
	if (state->secret_watcher == NULL) {
		TSError("[kubernetes_tls] Cannot create Secret watcher: %s",
			strerror(errno));
		free(state);
		return;
	}

	watcher_set_callback(state->secret_watcher, secret_cb, state);
	watcher_run(state->secret_watcher, 0);

	if ((state->rebuild_cont = TSContCreate(handle_rebuild, TSMutexCreate())) == NULL) {
		TSError("[kubernetes_tls] Failed to create continuation.");
		return;
	}

	TSContDataSet(state->rebuild_cont, state);

	if ((state->map_cont = TSContCreate(handle_map, NULL)) == NULL) {
		TSError("[kubernetes_tls] Failed to create continuation");
		return;
	}

	TSHttpHookAdd(TS_SSL_SNI_HOOK, state->map_cont);

	info.plugin_name = "Kubernetes TLS loader";
	info.vendor_name = "Torchbox, Ltd.";
	info.support_email = "sysadmin@torchbox.com";
	if (TSPluginRegister(&info) != TS_SUCCESS) {
		TSError("[kubernetes_tls] Plugin registration failed.");
		return;
	}
}
