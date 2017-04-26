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

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<getopt.h>
#include	<regex.h>

#include	<ts/ts.h>
#include	<ts/remap.h>

#include	<openssl/ssl.h>

#include	"watcher.h"
#include	"api.h"
#include	"config.h"
#include	"plugin.h"
#include	"synth.h"

static void
remap_host_free(struct remap_host *host)
{
size_t	i, j;
	for (i = 0; i < host->rh_npaths; i++) {
		for (j = 0; j < host->rh_paths[i].rp_naddrs; j++)
			free(host->rh_paths[i].rp_addrs[j]);

		free(host->rh_paths[i].rp_prefix);
		free(host->rh_paths[i].rp_addrs);
		free(host->rh_paths[i].rp_app_root);
		free(host->rh_paths[i].rp_rewrite_target);
		regfree(&host->rh_paths[i].rp_regex);
	}
	free(host->rh_paths);

	for (j = 0; j < host->rh_default.rp_naddrs; j++)
		free(host->rh_default.rp_addrs[j]);
	free(host->rh_default.rp_addrs);

	regfree(&host->rh_default.rp_regex);

	if (host->rh_ctx)
		TSSslContextDestroy((TSSslContext) host->rh_ctx);

	free(host);
}

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

	if (strcmp(svc->sv_type, "ExternalName") == 0) {
	char	abuf[512];

		snprintf(abuf, sizeof(abuf), "%s:%s", svc->sv_external_name,
			 port_name);
		TSDebug("kubernetes", "        found an ExternalName: %s",
			abuf);
		rp->rp_naddrs = 1;
		rp->rp_addrs = calloc(1, sizeof(char *));
		rp->rp_addrs[0] = strdup(abuf);
		return;
	}

	if ((port = hash_find(svc->sv_ports, find_port_name,
			      (void *)port_name)) == NULL)
		return;

	eps = namespace_get_endpoints(ctx->ns, svc->sv_name);
	if (eps == NULL)
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

			TSDebug("kubernetes", "        add host %s:%d",
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
size_t		 i;
char		*s;

	for (i = 0; i < rule->ir_npaths; i++) {
	ingress_path_t		*path = &rule->ir_paths[i];
	struct remap_path	*rp;
	service_t		*svc;

		svc = namespace_get_service(ctx->ns,
					    path->ip_service_name);
		if (svc == NULL)
			continue;

		TSDebug("kubernetes", "      path <%s> -> service <%s/%s>",
			path->ip_path, svc->sv_namespace, svc->sv_name);

		if (path->ip_path) {
		int	rerr;
		char	*pregex;
		regex_t	regex;
			if (path->ip_path[0] != '/')
				continue;

			/*
			 * Path is required to begin with '/'.  However, when
			 * TS provides us the request path later to match
			 * against, the leading '/' is stripped.  Strip it here
			 * as well to make matching the request easier.
			 */
			if ((pregex = malloc(strlen(path->ip_path) + 1)) == NULL)
				continue;
			sprintf(pregex, "^%s", path->ip_path + 1);
			rerr = regcomp(&regex, pregex, REG_EXTENDED);
			free(pregex);
			if (rerr != 0) {
				regfree(&regex);
				continue;
			}

			rh->rh_paths = realloc(rh->rh_paths,
					       sizeof(struct remap_path)
						 * (rh->rh_npaths + 1));
			rp = &rh->rh_paths[rh->rh_npaths];
			bzero(rp, sizeof(*rp));
			++rh->rh_npaths;

			rp->rp_addrs = NULL;
			rp->rp_naddrs = 0;
			rp->rp_prefix = strdup(path->ip_path);
			bcopy(&regex, &rp->rp_regex, sizeof(regex));
		} else {
			rp = &rh->rh_default;
		}

		/*
		 * Set configuration on this rp from annotations.
		 */

		/* cache-generation: set TS cache generation */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/cache-generation");
		if (s)
			rp->rp_cache_gen = atoi(s);

		/* cache-enable: if false, disable caching entirely */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/cache-enable");
		if (s && !strcmp(s, "false"))
			rp->rp_cache = 0;
		else
			rp->rp_cache = 1;

		/* hsts-max-age: enable hsts */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/hsts-max-age");
		if (s)
			rp->rp_hsts_max_age = atoi(s);

		/* hsts-include-subdomains: if set, hsts includes subdomains */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/hsts-include-subdomains");
		if (s && !strcmp(s, "true"))
			rp->rp_hsts_subdomains = 1;
		else
			rp->rp_hsts_subdomains = 0;

		/* follow-redirects: if set, TS will resolve 3xx responses itself */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/follow-redirects");
		if (s && !strcmp(s, "true"))
			rp->rp_follow_redirects = 1;
		else
			rp->rp_follow_redirects = 0;

		/* secure-backends: use TLS for backend connections */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/secure-backends");
		if (s && !strcmp(s, "true"))
			rp->rp_secure_backends = 1;
		else
			rp->rp_secure_backends = 0;

		/* preserve-host: use origin request host header */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/preserve-host");
		if (s && !strcmp(s, "false"))
			rp->rp_preserve_host = 0;
		else
			rp->rp_preserve_host = 1;

		/* app-root: enforce url prefix */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/app-root");
		if (s)
			rp->rp_app_root = strdup(s);

		/* rewrite-target: rewrite URL path */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/rewrite-target");
		/*
		 * Strip the leading '/' from rewrite-target, because it's
		 * already there when we mangle the path later.
		 */
		if (s && *s == '/')
			rp->rp_rewrite_target = strdup(s + 1);

		/*
		 * Add the endpoints for this service's backends.
		 */
		rebuild_add_endpoints(ctx, svc, rp,
				      path->ip_service_port);
	}
}

static void
rebuild_ingress_tls(struct rebuild_ctx *ctx, ingress_t *ing,
		    ingress_tls_t *itls)
{
secret_t		*secret;
size_t			 i;

	TSDebug("kubernetes", "    secret %s (%d hosts):",
		itls->it_secret_name, (int) itls->it_nhosts);

	if ((secret = namespace_get_secret(ctx->ns, itls->it_secret_name)) == NULL) {
		TSDebug("kubernete", "Could not find secret [%s]",
			itls->it_secret_name);
		return;
	}

	for (i = 0; i < itls->it_nhosts; i++) {
	const char		*hostname = itls->it_hosts[i];
	struct remap_host	*rh;
	char			*s;

		if ((rh = hash_get(ctx->map, hostname)) == NULL) {
			TSDebug("kubernetes", "      new host");
			rh = calloc(1, sizeof(*rh));
			hash_set(ctx->map, hostname, rh);
		} else {
			TSDebug("kubernetes", "      existing host");
		}

		if ((rh->rh_ctx = secret_make_ssl_ctx(secret)) == NULL) {
			TSDebug("kubernetes", "      %s: can't make ctx",
				hostname);
			return;
		}
		TSDebug("kubernetes", "      %s: added with CTX[%p]",
			hostname, rh->rh_ctx);

		s = hash_get(ing->in_annotations,
			     "ingress.kubernetes.io/ssl-redirect");
		if (s && !strcmp(s, "false"))
			rh->rh_no_ssl_redirect = 1;

		s = hash_get(ing->in_annotations,
			     "ingress.kubernetes.io/force-ssl-redirect");
		if (s && !strcmp(s, "true"))
			rh->rh_force_ssl_redirect = 1;
	}
}

static void
rebuild_ingress(hash_t hs, const char *ingname, void *value, void *data)
{
struct rebuild_ctx	*ctx = data;
ingress_t		*ing = value;
size_t			 i;

	TSDebug("kubernetes", "  ingress %s:", ingname);
	ctx->ingress = ing;

	/*
	 * Rebuild TLS state.
	 */
	for (i = 0; i < ing->in_ntls; i++)
		rebuild_ingress_tls(ctx, ing, &ing->in_tls[i]);

	/* Rebuild remap state.
	 */
	for (i = 0; i < ing->in_nrules; i++) {
	struct remap_host	*rh;
	const char		*hostname = ing->in_rules[i].ir_host;

		TSDebug("kubernetes", "    hostname %s:", hostname);

		/*
		 * If this host already exists (because another Ingress uses
		 * it), then add paths to the existing host; otherwise, create
		 * a new one.
		 */
		if ((rh = hash_get(ctx->map, hostname)) == NULL) {
			TSDebug("kubernetes", "      new host");
			rh = calloc(1, sizeof(*rh));
			hash_set(ctx->map, hostname, rh);
		} else {
			TSDebug("kubernetes", "      existing host");
		}

		rebuild_make_host(ctx, rh, &ing->in_rules[i]);
	}
}

static void
rebuild_namespace(hash_t hs, const char *nsname, void *value, void *data)
{
struct rebuild_ctx	*ctx = data;
namespace_t		*ns = value;

	TSDebug("kubernetes", "namespace %s:", nsname);
	ctx->ns = ns;
	hash_foreach(ns->ns_ingresses, rebuild_ingress, ctx);
}

void
rebuild_maps(void)
{
struct rebuild_ctx	ctx;

	TSMutexLock(state->cluster_lock);
	if (!state->changed) {
		TSDebug("kubernetes", "rebuild_maps: no changes");
		TSMutexUnlock(state->cluster_lock);
		return;
	}

	TSDebug("kubernetes", "rebuild_maps: running");
	ctx.map = hash_new(127, (hash_free_fn) remap_host_free);
	hash_foreach(state->cluster->cs_namespaces, rebuild_namespace, &ctx);

	state->changed = 0;
	TSMutexUnlock(state->cluster_lock);

	TSConfigSet(state->cfg_slot, ctx.map, (TSConfigDestroyFunc)hash_free);
}

/*
 * Search the list of paths in a remap_host for one that matches the provided
 * path, and return it.  If pfxs is non-NULL, the length of the portion of the
 * request path that was matched by the remap_path will be stored.
 */
static struct remap_path *
find_path(struct remap_host *rh, const char *path, size_t *pfxs)
{
size_t	i = 0;

	for (i = 0; i < rh->rh_npaths; i++) {
	struct remap_path	*rp = &rh->rh_paths[i];
	regmatch_t		 matches[1];

		if (regexec(&rp->rp_regex, path, 1, matches, 0) == 0) {
			TSDebug("kubernetes", "find_path: path [%s] matched [%s]",
				path, rp->rp_prefix);

			if (pfxs)
				*pfxs = matches[0].rm_eo - matches[0].rm_so;
			return rp;
		}
		TSDebug("kubernetes", "find_path: path [%s] did not match [%s]",
			path, rp->rp_prefix);
	}

	if (pfxs)
		*pfxs = 0;
	TSDebug("kubernetes", "find_path: returning default for [%s]", path);
	return &rh->rh_default;
}

/*
 * handle_remap: called in READ_REQUEST_HDR_HOOK.  Match the incoming request
 * to an Ingress path (remap_path), apply any configurations from annotations,
 * and either set the host to proxy the request to the backend, or return
 * our own error or redirect response.
 *
 * This function takes the map lock on every request, so it is a contention
 * point.  The map could be made refcounted to reduce the amount of time we
 * have to hold the map lock.
 */
int
handle_remap(TSCont contn, TSEvent event, void *edata)
{
int			 pod_port, len, hostn;
char			*pod_host = NULL, *requrl = NULL;
const char		*cs;
char			*hbuf = NULL, *pbuf = NULL, *s;
struct remap_host	*rh;
struct remap_path	*rp;
size_t			 poffs;
TSMBuffer		 reqp;
TSMLoc			 hdr_loc = NULL, url_loc = NULL, host_hdr;
TSHttpTxn		 txnp = (TSHttpTxn) edata;
TSConfig		 map_cfg = NULL;
hash_t			 map;

	map_cfg = TSConfigGet(state->cfg_slot);
	map = TSConfigDataGet(map_cfg);

	/* Not initialised yet? */
	if (!map)
		goto cleanup;


	/* Fetch the request and the URL. */
	TSHttpTxnClientReqGet(txnp, &reqp, &hdr_loc);
	TSHttpHdrUrlGet(reqp, hdr_loc, &url_loc);

	/*
	 * Fetch the host header, which could either be in the Host: header,
	 * or in the request path for a proxy-style request (GET http://).
	 * We need to handle both cases.
	 */
	host_hdr = TSMimeHdrFieldFind(reqp, hdr_loc, "Host", 4);
	if (host_hdr) {
		/*
		 * TS fails a request for too many host headers anymore, but
		 * check here just to be sure.
		 */
		if (TSMimeHdrFieldValuesCount(reqp, hdr_loc, host_hdr) != 1) {
			TSDebug("kubernetes", "too many hosts in request?");
			goto cleanup;
		}

		cs = TSMimeHdrFieldValueStringGet(reqp, hdr_loc, host_hdr, 0, &len);
	} else {
		cs = TSHttpHdrHostGet(reqp, hdr_loc, &len);
		if (cs == NULL) {
			/*
			 * If there's no host in the URL and no host header
			 * either, we can't do anything with this request.
			 * Let TS fail it.
			 */
			TSDebug("kubernetes", "cannot get request host");
			goto cleanup;
		}
	}

	/* create a mutable, nul-terminated copy of the host */
	hbuf = malloc(len + 1);
	bcopy(cs, hbuf, len);
	hbuf[len] = 0;
	if ((s = strchr(hbuf, ':')) != NULL)
		*s = '\0';

	/*
	 * Look for a remap_host for this hostname.  If there isn't one, we
	 * have no configuration for this host and there's nothing more to do.
	 */
	if ((rh = hash_get(map, hbuf)) == NULL) {
		TSDebug("kubernetes", "host <%s> map not found", hbuf);
		goto cleanup;
	}

	/*
	 * Fetch the URL path.
	 */
	cs = TSUrlPathGet(reqp, url_loc, &len);
	if (cs) {
		pbuf = malloc(len + 1);
		bcopy(cs, pbuf, len);
		pbuf[len] = 0;
	} else {
		pbuf = strdup("/");
	}

	/*
	 * Find a remap_path for this host that matches the request path;
	 * if no path is found, pass on this request and let the default
	 * backend return a 404.
	 */
	if ((rp = find_path(rh, pbuf, &poffs)) == NULL) {
		TSDebug("kubernetes", "host <%s>, path <%s> not found",
			hbuf, pbuf);
		goto cleanup;
	}

	/*
	 * If the ingress has no backends, return an error.
	 */
	if (rp->rp_naddrs == 0) {
	synth_t	*sy;
		TSDebug("kubernetes", "host <%s>: no addrs", hbuf);
		sy = synth_new(503, "Service unavailable");
		synth_add_header(sy, "Content-Type", "text/plain; charset=UTF-8");
		synth_set_body(sy, "No backends are available to service this "
				"request.  Please try again later.\r\n");
		synth_intercept(sy, txnp);
		goto cleanup;
	}

	if ((cs = TSUrlSchemeGet(reqp, url_loc, &len)) == NULL) {
		TSDebug("kubernetes", "<%s>: could not get url scheme", requrl);
		goto cleanup;
	}

	/*
	 * If the Ingress has TLS configured, then redirect to TLS unless
	 * ssl-redirect is set to false.
	 *
	 * If the Ingress does not have TLS configured, redirect to TLS if
	 * force-ssl-redirect is set to true.
	 */
	if (!TSHttpTxnClientProtocolStackContains(txnp, "tls") &&
	    ((rh->rh_ctx && !rh->rh_no_ssl_redirect)
	     || rh->rh_force_ssl_redirect)) {
	const char	*newp;
	synth_t		*sy;
	TSMBuffer	 newurl;
	TSMLoc		 new_loc;

		/*
		 * Construct the URL to redirect to.
		 */
		newurl = TSMBufferCreate();
		TSUrlClone(newurl, reqp, url_loc, &new_loc);
		cs = TSUrlSchemeGet(newurl, new_loc, &len);

		if (len == 4 && !memcmp(cs, "http", 4))
			newp = "https";
		else if (len == 2 && !memcmp(cs, "ws", 2))
			newp = "wss";
		else
			newp = "https";

		TSUrlSchemeSet(newurl, new_loc, newp, strlen(newp));
		TSUrlHostSet(newurl, new_loc, hbuf, strlen(hbuf));
		s = TSUrlStringGet(newurl, new_loc, &len);
		TSHandleMLocRelease(newurl, TS_NULL_MLOC, new_loc);
		TSMBufferDestroy(newurl);

		/*
		 * Return a synthetic response to redirect.
		 */
		sy = synth_new(301, "Moved");
		synth_add_header(sy, "Location", s);
		synth_add_header(sy, "Content-Type", "text/plain;charset=UTF-8");
		synth_set_body(sy, "The requested document has moved.\r\n");
		synth_intercept(sy, txnp);
		TSfree(s);

		goto cleanup;
	}

	/*
	 * Set cache generation if it's set on the Ingress.  If it's not set,
	 * just set it to zero.
	 */
	TSHttpTxnConfigIntSet(txnp, TS_CONFIG_HTTP_CACHE_GENERATION, rp->rp_cache_gen);

	/*
	 * Enable caching, unless it's been cached on the Ingress.
	 */
	TSHttpTxnConfigIntSet(txnp, TS_CONFIG_HTTP_CACHE_HTTP, rp->rp_cache);

	/*
	 * Send HSTS headers.
	 */
	if (rp->rp_hsts_max_age)
		TSHttpTxnConfigIntSet(txnp, TS_CONFIG_SSL_HSTS_MAX_AGE,
				      rp->rp_hsts_max_age);
	TSHttpTxnConfigIntSet(txnp, TS_CONFIG_SSL_HSTS_INCLUDE_SUBDOMAINS, 1);

	/*
	 * If the Ingress has app-root set, then any request not inside the
	 * app root should be redirected.
	 */
	cs = TSUrlPathGet(reqp, url_loc, &len);

	if (rp->rp_app_root && (!cs
	    || (size_t)len < strlen(rp->rp_app_root + 1)
	    || memcmp(cs, rp->rp_app_root + 1, strlen(rp->rp_app_root + 1)))) {
	synth_t	*sy;
	TSMBuffer	 newurl;
	TSMLoc		 new_loc;

		/*
		 * Construct the URL to redirect to.
		 */
		newurl = TSMBufferCreate();
		TSUrlClone(newurl, reqp, url_loc, &new_loc);

		/* Strip the leading / from the path */
		TSUrlPathSet(newurl, new_loc, rp->rp_app_root + 1,
			     strlen(rp->rp_app_root) - 1);

		s = TSUrlStringGet(newurl, new_loc, &len);
		sy = synth_new(301, "Redirected");
		synth_add_header(sy, "Location", s);
		synth_add_header(sy, "Content-Type",
				 "text/plain; charset=UTF-8");
		synth_set_body(sy, "The requested document is found "
				"elsewhere.\r\n");
		synth_intercept(sy, txnp);

		TSHandleMLocRelease(newurl, TS_NULL_MLOC, new_loc);
		TSMBufferDestroy(newurl);
		TSfree(s);

		goto cleanup;
	}

	/*
	 * Tell TS to follow redirects if configured on the Ingress.
	 */
	if (rp->rp_follow_redirects) {
		TSHttpTxnConfigIntSet(txnp,
				TS_CONFIG_HTTP_ENABLE_REDIRECTION, 1);
		TSHttpTxnConfigIntSet(txnp,
				TS_CONFIG_HTTP_REDIRECT_USE_ORIG_CACHE_KEY, 1);
	}

	/*
	 * Pick a random backend endpoint to route the request to.
	 */
	hostn = rand() / (RAND_MAX / rp->rp_naddrs + 1);

	pod_host = strdup(rp->rp_addrs[hostn]);
	TSDebug("kubernetes", "remapped to %s", pod_host);

	/*
	 * Usually, we want to preserve the request host header so the backend
	 * can use it.  If preserve-host is set on the Ingress, then we instead
	 * replace any host header in the request with the backend host.
	 */
	if (!rp->rp_preserve_host) {
		TSHttpTxnConfigIntSet(txnp, TS_CONFIG_URL_REMAP_PRISTINE_HOST_HDR, 0);
		if (host_hdr)
			TSMimeHdrFieldValueStringSet(reqp, hdr_loc, host_hdr, 0,
						     pod_host, strlen(pod_host));
	}

	/*
	 * If the Ingress has rewrite-target set, then replace the matched
	 * part of the path (stored in poffs by find_path()) with the target.
	 */
	if (rp->rp_rewrite_target) {
	char	*newp;
	size_t	 nlen = strlen(pbuf) + strlen(rp->rp_rewrite_target) - poffs;
		newp = malloc(nlen + 1);
		snprintf(newp, nlen + 1, "%s%s", rp->rp_rewrite_target,
			 pbuf + poffs);
		TSUrlPathSet(reqp, url_loc, newp, nlen);
		free(newp);
	}

	/*
	 * Strip the port from the host and set the backend in the URL.  This
	 * is equivalent to remapping the request.
	 */
	if ((s = strchr(pod_host, ':')) != NULL) {
		*s++ = 0;
		pod_port = atoi(s);
	} else goto cleanup;

	if (TSUrlHostSet(reqp, url_loc, pod_host, strlen(pod_host)) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set request host", requrl);
		goto cleanup;
	}

	if (TSUrlPortSet(reqp, url_loc, pod_port) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set request port", requrl);
		goto cleanup;
	}

	/*
	 * Decide what protocol to use to communicate with the backend.  By
	 * default we use http or ws, even if the request was https or wss.
	 * If the Ingress has secure-backends set, then we always use https
	 * or wss, even if the request was http or ws.
	 *
	 * Currently, there's no way to indicate that the protocol from the
	 * request should be preserved.
	 */
	if ((cs = TSUrlSchemeGet(reqp, url_loc, &len)) != NULL) {
	const char	*newp = NULL;

		if (len >= 4 && !memcmp(cs, "http", 4)) {
			if (rp->rp_secure_backends)
				newp = "https";
			else
				newp = "http";
		} else if (len >= 2 && !memcmp(cs, "ws", 2)) {
			if (rp->rp_secure_backends)
				newp = "wss";
			else
				newp = "ws";
		}

		if (newp)
			TSUrlSchemeSet(reqp, url_loc, newp, strlen(newp));
	}

	/*
	 * We already remapped this request, so skip any further remapping.
	 * This also prevents TS from failing the request if remap_required
	 * is set.
	 */
	TSSkipRemappingSet(txnp, 1);

cleanup:
	TSConfigRelease(state->cfg_slot, map_cfg);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
	if (url_loc)
		TSHandleMLocRelease(reqp, hdr_loc, url_loc);
	if (hdr_loc)
		TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdr_loc);
	free(pod_host);
	free(pbuf);
	free(hbuf);
	return TS_SUCCESS;
}
