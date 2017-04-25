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
#include	<regex.h>

#include	<ts/ts.h>
#include	<ts/remap.h>

#include	"watcher.h"
#include	"api.h"
#include	"config.h"

struct remap_path {
	char	 *rp_prefix;
	regex_t	  rp_regex;
	char	**rp_addrs;
	size_t	  rp_naddrs;
};

struct remap_host {
	struct remap_path	*rh_paths;
	size_t			 rh_npaths;
	struct remap_path	 rh_default;
};

static void
remap_host_free(struct remap_host *host)
{
size_t	i;
	for (i = 0; i < host->rh_npaths; i++) {
		free(host->rh_paths[i].rp_prefix);
		free(host->rh_paths[i].rp_addrs);
		regfree(&host->rh_paths[i].rp_regex);
	}

	free(host->rh_default.rp_addrs);
	regfree(&host->rh_default.rp_regex);
}

struct remap_state {
	TSMutex		 cluster_lock;
	cluster_t	*cluster;
	watcher_t	 ingress_watcher;
	watcher_t	 secret_watcher;
	watcher_t	 service_watcher;
	watcher_t	 endpoints_watcher;
	int		 changed;

	TSMutex		 map_lock;
	hash_t		 map;

	TSCont		 rebuild_cont;
};

struct rebuild_ctx {
	struct remap_state	*state;
	namespace_t		*namespace;
	hash_t			 map;
};

static int
find_port_name(hash_t hs, const char *key, void *value, void *data)
{
const char	*port_name = data;
service_port_t	*port = value;
int		 n;

	if (port->sp_protocol != SV_P_TCP)
		return 0;

	if (strcmp(port_name, port->sp_name) == 0)
		return 1;

	if ((n = atoi(port_name)) != 0)
		if (n == port->sp_port)
			return 1;

	return 0;
}

static void
rebuild_add_endpoints(
	struct rebuild_ctx *ctx,
	service_t *svc,
	struct remap_path *rp,
	const char *port_name)
{
service_port_t	*port;
endpoints_t	*eps;
size_t		 i, j;

	eps = namespace_get_endpoints(ctx->namespace, svc->sv_name);
	if (eps == NULL)
		return;

	if ((port = hash_find(svc->sv_ports, find_port_name,
			      (void *)port_name)) == NULL)
		return;

	for (i = 0; i < eps->ep_nsubsets; i++) {
	endpoints_subset_t	*es = &eps->ep_subsets[i];
	endpoints_port_t	*epp;

		epp = hash_get(es->es_ports, port->sp_name);
		if (epp == NULL)
			continue;

		rp->rp_addrs = realloc(rp->rp_addrs,
				sizeof(char *) * (rp->rp_naddrs + es->es_naddrs));

		for (j = 0; j < es->es_naddrs; j++) {
		endpoints_address_t *addr = &es->es_addrs[j];
		char		     buf[512];

			TSDebug("kubernetes_remap", "        add host %s:%d",
				addr->ea_ip, epp->et_port);

			snprintf(buf, sizeof(buf), "%s:%d",
					addr->ea_ip, epp->et_port);
			rp->rp_addrs[rp->rp_naddrs + j] = strdup(buf);
		}

		rp->rp_naddrs += es->es_naddrs;
	}
}

static void
rebuild_make_host(struct rebuild_ctx *ctx,
		  struct remap_host *rh,
		  ingress_rule_t *rule)
{
size_t			 i;

	for (i = 0; i < rule->ir_npaths; i++) {
	ingress_path_t		*path = &rule->ir_paths[i];
	struct remap_path	*rp;
	service_t		*svc;

		svc = namespace_get_service(ctx->namespace,
					    path->ip_service_name);
		if (svc == NULL)
			continue;

		TSDebug("kubernetes_remap", "      path <%s> -> service <%s/%s>",
			path->ip_path, svc->sv_namespace, svc->sv_name);

		if (path->ip_path) {
		int	rerr;
		char	*pregex;
		regex_t	regex;
			if (path->ip_path[0] != '/')
				continue;

			if ((pregex = malloc(strlen(path->ip_path) + 1)) == NULL)
				continue;
			sprintf(pregex, "^%s", path->ip_path);
			rerr = regcomp(&regex, pregex, REG_NOSUB | REG_EXTENDED);
			free(pregex);
			if (rerr != 0) {
				regfree(&regex);
				continue;
			}

			rh->rh_paths = realloc(rh->rh_paths, 
				       sizeof(struct remap_path)
				         * (rh->rh_npaths + 1));
			rp = &rh->rh_paths[rh->rh_npaths];
			++rh->rh_npaths;

			rp->rp_addrs = NULL;
			rp->rp_naddrs = 0;
			rp->rp_prefix = strdup(path->ip_path);
			bcopy(&regex, &rp->rp_regex, sizeof(regex));
		} else {
			rp = &rh->rh_default;
		}

		rebuild_add_endpoints(ctx, svc, rp,
				      path->ip_service_port);
	}
}

static void
rebuild_ingress(hash_t hs, const char *ingname, void *value, void *data)
{
struct rebuild_ctx	*ctx = data;
ingress_t		*ing = value;
size_t			 i;

	TSDebug("kubernetes_remap", "  ingress %s:", ingname);

	for (i = 0; i < ing->in_nrules; i++) {
	struct remap_host	*rh;
	const char		*hostname = ing->in_rules[i].ir_host;

		TSDebug("kubernetes_remap", "    hostname %s:", hostname);

		/*
		 * If this host already exists (because another Ingress uses
		 * it), then add paths to the existing host; otherwise, create
		 * a new one.
		 */
		if ((rh = hash_get(ctx->map, hostname)) == NULL) {
			TSDebug("kubernetes_remap", "      new host");
			rh = calloc(1, sizeof(*rh));
			hash_set(ctx->map, hostname, rh);
		} else {
			TSDebug("kubernetes_remap", "      existing host");
		}

		rebuild_make_host(ctx, rh, &ing->in_rules[i]);
	}
	
}

static void
rebuild_namespace(hash_t hs, const char *nsname, void *value, void *data)
{
struct rebuild_ctx	*ctx = data;
namespace_t		*ns = value;

	TSDebug("kubernetes_remap", "namespace %s:", nsname);
	ctx->namespace = ns;
	hash_foreach(ns->ns_ingresses, rebuild_ingress, ctx);
}

static int
handle_rebuild(TSCont contn, TSEvent evt, void *edata)
{
struct remap_state	*state = TSContDataGet(contn);
hash_t			 old_map;
struct rebuild_ctx	 ctx;

	TSMutexLock(state->cluster_lock);
	if (!state->changed) {
		TSDebug("kubernetes_tls", "rebuild_tls_map: no changes");
		TSMutexUnlock(state->cluster_lock);
		return TS_SUCCESS;
	}

	TSDebug("kubernetes_tls", "rebuild_tls_map: running");
	ctx.map = hash_new(127, (hash_free_fn) remap_host_free);
	hash_foreach(state->cluster->cs_namespaces, rebuild_namespace, &ctx);
	state->changed = 0;

	TSMutexLock(state->map_lock);
	old_map = state->map;
	state->map = ctx.map;
	TSMutexUnlock(state->map_lock);

	TSMutexUnlock(state->cluster_lock);

	if (old_map)
		hash_free(old_map);

	return TS_SUCCESS;
}

TSReturnCode
TSRemapInit(TSRemapInterface *api, char *errbuf, int bufsz)
{
	return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *instance)
{
}

static struct remap_path *
find_path(struct remap_host *rh, const char *path)
{
size_t	i = 0;
	for (i = 0; i < rh->rh_npaths; i++) {
	struct remap_path	*rp = &rh->rh_paths[i];

		if (regexec(&rp->rp_regex, path, 0, NULL, 0) == 0)
			return rp;
	}

	return &rh->rh_default;
}

TSRemapStatus
TSRemapDoRemap(void *instance, TSHttpTxn txn, TSRemapRequestInfo *rri)
{
int			 pod_port, len, hostn;
char			*pod_host = NULL, *requrl = NULL;
const char		*cs;
char			*hbuf = NULL, *pbuf = NULL, *s;
struct remap_host	*rh;
struct remap_path	*rp;
struct remap_state	*state = instance;

	TSMutexLock(state->map_lock);

	/* fetch url host */
	cs = TSUrlHostGet(rri->requestBufp, rri->requestUrl, &len);
	if (cs == NULL) {
		TSDebug("kubernetes_remap", "cannot get URL host");
		goto error;
	}

	hbuf = malloc(len + 1);
	bcopy(cs, hbuf, len);
	hbuf[len] = 0;

	/* fetch the remap_host for this host */
	if ((rh = hash_get(state->map, hbuf)) == NULL) {
		TSDebug("kubernetes_remap", "host <%s> map not found", hbuf);
		goto error;
	}

	/* fetch url path */
	cs = TSUrlPathGet(rri->requestBufp, rri->requestUrl, &len);
	if (cs) {
		pbuf = malloc(len + 1);
		bcopy(cs, pbuf, len);
		pbuf[len] = 0;
	} else {
		pbuf = strdup("/");
	}

	/* find the route_path that matches this path */
	if ((rp = find_path(rh, pbuf)) == NULL) {
		TSDebug("kubernetes_remap", "host <%s>, path <%s> not found",
			hbuf, pbuf);
		goto error;
	}

	hostn = rand() / (RAND_MAX / rp->rp_naddrs + 1);

	pod_host = strdup(rp->rp_addrs[hostn]);
	if ((s = strchr(pod_host, ':')) != NULL) {
		*s++ = 0;
		pod_port = atoi(s);
	} else goto error;

	TSDebug("kubernetes_remap", "remapped to %s:%d", pod_host, pod_port);

	if (TSUrlHostSet(rri->requestBufp, rri->requestUrl,
			 pod_host, strlen(pod_host)) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set remap URL host", requrl);
		goto error;
	}

	if (TSUrlPortSet(rri->requestBufp, rri->requestUrl, pod_port) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set remap URL port", requrl);
		goto error;
	}

	if (TSUrlSchemeSet(rri->requestBufp, rri->requestUrl,
			   "http", 4) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set remap URL scheme", requrl);
		goto error;
	}

	TSMutexUnlock(state->map_lock);
	free(pod_host);
	free(pbuf);
	free(hbuf);
	return TSREMAP_DID_REMAP;

error:
	TSMutexUnlock(state->map_lock);
	free(pod_host);
	free(pbuf);
	free(hbuf);
	return TSREMAP_NO_REMAP;
}

void
ingress_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
ingress_t		*ing;
namespace_t		*ns;
struct remap_state	*state = data;

	if ((ing = ingress_make(obj)) == NULL) {
		TSError("[kubernetes_remap] Could not parse Ingress object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes_remap", "something happened with an ingress: %s/%s",
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
struct remap_state	*state = data;

	if ((secret = secret_make(obj)) == NULL) {
		TSError("[kubernetes_remap] Could not parse Secret object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes_remap", "something happened with a secret: %s/%s",
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
endpoints_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
endpoints_t		*endpoints;
namespace_t		*ns;
struct remap_state	*state = data;

	if ((endpoints = endpoints_make(obj)) == NULL) {
		TSError("[kubernetes_remap] Could not parse Endpoints object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes_remap", "something happened with a endpoints: %s/%s",
		endpoints->ep_namespace, endpoints->ep_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, endpoints->ep_namespace);
	if (ev == WT_DELETED) {
		namespace_del_endpoints(ns, endpoints->ep_name);
	} else {
		namespace_put_endpoints(ns, endpoints);
	}

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}
	TSMutexUnlock(state->cluster_lock);
}

void
service_cb(watcher_t wt, wt_event_type_t ev, json_object *obj, void *data)
{
service_t		*service;
namespace_t		*ns;
struct remap_state	*state = data;

	if ((service = service_make(obj)) == NULL) {
		TSError("[kubernetes_remap] Could not parse Service object: %s",
			json_object_get_string(obj));
		return;
	}

	TSDebug("kubernetes_remap", "something happened with a service: %s/%s",
		service->sv_namespace, service->sv_name);

	TSMutexLock(state->cluster_lock);

	ns = cluster_get_namespace(state->cluster, service->sv_namespace);
	if (ev == WT_DELETED) {
		namespace_del_service(ns, service->sv_name);
	} else {
		namespace_put_service(ns, service);
	}

	if (!state->changed) {
		state->changed = 1;
		TSContSchedule(state->rebuild_cont, 1000, TS_THREAD_POOL_DEFAULT);
	}
	TSMutexUnlock(state->cluster_lock);
}

TSReturnCode
TSRemapNewInstance(int argc, char **argv, void **instance,
		   char *errbuf, int errbuf_size)
{
struct remap_state	*state;
k8s_config_t		*conf;

	SSL_library_init();
	SSL_load_error_strings();

	if (argc < 3) {
		snprintf(errbuf, errbuf_size, "configuration file not specified");
		return TS_ERROR;
	}

	if ((conf = k8s_config_load(argv[2])) == NULL) {
		snprintf(errbuf, errbuf_size, "failed to load configuration");
		return TS_ERROR;
	}

	if ((state = calloc(1, sizeof(*state))) == NULL) {
		snprintf(errbuf, errbuf_size, "cannot create remap_state: %s",
			strerror(errno));
		return TS_ERROR;
	}

	state->map_lock = TSMutexCreate();
	state->cluster_lock = TSMutexCreate();
	state->cluster = cluster_make();
	*instance = state;

	/*
	 * Create watcher for Ingresses.
	 */
	state->ingress_watcher = watcher_create(conf,
					 "/apis/extensions/v1beta1/ingresses");
	if (state->ingress_watcher == NULL) {
		snprintf(errbuf, errbuf_size, "cannot create Ingress watcher: %s",
			strerror(errno));
		free(state);
		return TS_ERROR;
	}

	watcher_set_callback(state->ingress_watcher, ingress_cb, state);
	watcher_run(state->ingress_watcher, 0);

	/*
	 * Create watcher for Secrets
	 */
	state->secret_watcher = watcher_create(conf, "/api/v1/secrets");
	if (state->secret_watcher == NULL) {
		snprintf(errbuf, errbuf_size, "Cannot create Secret watcher: %s",
			strerror(errno));
		free(state);
		return TS_ERROR;
	}

	watcher_set_callback(state->secret_watcher, secret_cb, state);
	watcher_run(state->secret_watcher, 0);

	/*
	 * Create watcher for Services
	 */
	state->service_watcher = watcher_create(conf, "/api/v1/services");
	if (state->service_watcher == NULL) {
		snprintf(errbuf, errbuf_size, "Cannot create Service watcher: %s",
			strerror(errno));
		free(state);
		return TS_ERROR;
	}

	watcher_set_callback(state->service_watcher, service_cb, state);
	watcher_run(state->service_watcher, 0);

	/*
	 * Create watcher for Endpoints
	 */
	state->endpoints_watcher = watcher_create(conf, "/api/v1/endpoints");
	if (state->endpoints_watcher == NULL) {
		snprintf(errbuf, errbuf_size, "Cannot create Endpoints watcher: %s",
			strerror(errno));
		free(state);
		return TS_ERROR;
	}

	watcher_set_callback(state->endpoints_watcher, endpoints_cb, state);
	watcher_run(state->endpoints_watcher, 0);

	/*
	 * Create continuation to rebuild the map when it changes.
	 */
	if ((state->rebuild_cont = TSContCreate(handle_rebuild,
						TSMutexCreate())) == NULL) {
		snprintf(errbuf, errbuf_size, "Failed to create continuation.");
		return TS_ERROR;
	}

	TSContDataSet(state->rebuild_cont, state);
	return TS_SUCCESS;
}
