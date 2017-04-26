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

#include	<openssl/ssl.h>

#include	"watcher.h"
#include	"api.h"
#include	"config.h"
#include	"plugin.h"

static void
remap_host_free(struct remap_host *host)
{
size_t	i, j;
	for (i = 0; i < host->rh_npaths; i++) {
		for (j = 0; j < host->rh_paths[i].rp_naddrs; j++)
			free(host->rh_paths[i].rp_addrs[j]);

		free(host->rh_paths[i].rp_prefix);
		free(host->rh_paths[i].rp_addrs);
		regfree(&host->rh_paths[i].rp_regex);
	}
	free(host->rh_paths);

	for (j = 0; j < host->rh_default.rp_naddrs; j++)
		free(host->rh_default.rp_addrs[j]);
	free(host->rh_default.rp_addrs);

	regfree(&host->rh_default.rp_regex);

	if (host->rh_ctx)
		SSL_CTX_free(host->rh_ctx);

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

	eps = namespace_get_endpoints(ctx->ns, svc->sv_name);
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
size_t			 i;

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

			if ((pregex = malloc(strlen(path->ip_path) + 2)) == NULL)
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
	}
}

static void
rebuild_ingress(hash_t hs, const char *ingname, void *value, void *data)
{
struct rebuild_ctx	*ctx = data;
ingress_t		*ing = value;
size_t			 i;

	TSDebug("kubernetes", "  ingress %s:", ingname);

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
hash_t			old_map;
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

	TSMutexLock(state->map_lock);
	old_map = state->map;
	state->map = ctx.map;
	TSMutexUnlock(state->map_lock);

	TSMutexUnlock(state->cluster_lock);

	if (old_map)
		hash_free(old_map);

	return;
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

int
handle_remap(TSCont contn, TSEvent event, void *edata)
{
int			 pod_port, len, hostn;
char			*pod_host = NULL, *requrl = NULL;
const char		*cs;
char			*hbuf = NULL, *pbuf = NULL, *s;
struct remap_host	*rh;
struct remap_path	*rp;
TSMBuffer		 reqp;
TSMLoc			 hdr_loc = NULL, url_loc = NULL, host_hdr;
TSHttpTxn		 txnp = (TSHttpTxn) edata;

	/* Fetch the request */
	if (TSHttpTxnClientReqGet(txnp, &reqp, &hdr_loc) != TS_SUCCESS)
		goto cleanup;
	if (TSHttpHdrUrlGet(reqp, hdr_loc, &url_loc) != TS_SUCCESS)
		goto cleanup;

	TSMutexLock(state->map_lock);

	/* fetch url host */
	host_hdr = TSMimeHdrFieldFind(reqp, hdr_loc, "Host", 4);
	if (host_hdr) {
		if (TSMimeHdrFieldValuesCount(reqp, hdr_loc, host_hdr) != 1) {
			TSDebug("kubernetes", "too many hosts in request?");
			goto cleanup;
		}

		cs = TSMimeHdrFieldValueStringGet(reqp, hdr_loc, host_hdr, 0, &len);
	} else {
		cs = TSHttpHdrHostGet(reqp, hdr_loc, &len);
		if (cs == NULL) {
			TSDebug("kubernetes", "cannot get request host");
			goto cleanup;
		}
	}

	hbuf = malloc(len + 1);
	bcopy(cs, hbuf, len);
	hbuf[len] = 0;
	if ((s = strchr(hbuf, ':')) != NULL)
		*s = '\0';

	/* fetch the remap_host for this host */
	if ((rh = hash_get(state->map, hbuf)) == NULL) {
		TSDebug("kubernetes", "host <%s> map not found", hbuf);
		goto cleanup;
	}

	/* fetch url path */
	cs = TSUrlPathGet(reqp, url_loc, &len);
	if (cs) {
		pbuf = malloc(len + 1);
		bcopy(cs, pbuf, len);
		pbuf[len] = 0;
	} else {
		pbuf = strdup("/");
	}

	/* find the route_path that matches this path */
	if ((rp = find_path(rh, pbuf)) == NULL) {
		TSDebug("kubernetes", "host <%s>, path <%s> not found",
			hbuf, pbuf);
		goto cleanup;
	}

	if (rp->rp_naddrs == 0) {
		TSDebug("kubernetes", "host <%s>: no addrs", hbuf);
		goto cleanup;
	}

	hostn = rand() / (RAND_MAX / rp->rp_naddrs + 1);

	pod_host = strdup(rp->rp_addrs[hostn]);
	TSDebug("kubernetes", "remapped to %s", pod_host);

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

	if ((cs = TSUrlSchemeGet(reqp, url_loc, &len)) != NULL) {
	const char	*newp = NULL;

		if (len == 5 && !memcmp(cs, "https", 5))
			newp = "http";
		else if (len == 3 && !memcmp(cs, "wss", 3))
			newp = "ws";

		if (newp)
			TSUrlSchemeSet(reqp, url_loc, newp, strlen(newp));
	}

	TSSkipRemappingSet(txnp, 1);

cleanup:
	TSMutexUnlock(state->map_lock);
	if (url_loc)
		TSHandleMLocRelease(reqp, hdr_loc, url_loc);
	if (hdr_loc)
		TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdr_loc);
	free(pod_host);
	free(pbuf);
	free(hbuf);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
	return TS_SUCCESS;
}
