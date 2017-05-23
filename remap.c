/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<getopt.h>
#include	<regex.h>
#include	<ctype.h>

#include	<ts/ts.h>
#include	<ts/remap.h>

#include	<openssl/ssl.h>

#include	"watcher.h"
#include	"api.h"
#include	"config.h"
#include	"plugin.h"
#include	"synth.h"
#include	"base64.h"
#include	"ts_crypt.h"
#include	"auth.h"

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
	remap_path_t *rp,
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

static struct remap_auth_addr *
remap_path_get_addresses(const char *str)
{
struct remap_auth_addr	*list = NULL;
char			*mstr, *save, *saddr;

	if ((mstr = strdup(str)) == NULL)
		return NULL;

	for (saddr = strtok_r(mstr, " \t\n\r", &save); saddr != NULL;
	     saddr = strtok_r(NULL, " \t\n\r", &save)) {
	struct remap_auth_addr	*entry;
	char			*p = NULL;
	
		entry = calloc(1, sizeof(*entry));
		if ((p = strchr(saddr, '/')) != NULL) {
			*p++ = '\0';
			entry->ra_prefix_length = atoi(p);
		}

		if (inet_pton(AF_INET6, saddr,
			      entry->ra_addr_v6.s6_addr) == 1) {
			entry->ra_family = AF_INET6;
			if (p == NULL)
				entry->ra_prefix_length = 128;
		} else if (inet_pton(AF_INET, saddr, &entry->ra_addr_v4) == 1) {
			entry->ra_family = AF_INET;
			if (p == NULL)
				entry->ra_prefix_length = 32;
		} else {
			free(entry);
			continue;
		}

		entry->ra_next = list;
		list = entry;
	}
	     
	free(mstr);
	return list;
}

static void
remap_path_add_users(remap_path_t *rp, secret_t *secret)
{
char	*authdata = NULL;
char	*buf, *entry, *s;
size_t	 dlen;
ssize_t	 n;

	if ((authdata = hash_get(secret->se_data, "auth")) == NULL)
		return;

	dlen = strlen(authdata);
	s = buf = malloc(base64_decode_len(dlen) + 1);
	n = base64_decode(authdata, dlen, (unsigned char *)buf);

	if (n == -1) {
		free(buf);
		return;
	}

	buf[n] = '\0';

	while ((entry = strsep(&s, "\r\n")) != NULL) {
	char	*password, *rest;
		if ((password = strchr(entry, ':')) == NULL)
			continue;
		*password++ = '\0';

		if ((rest = strchr(password, ':')) != NULL)
			*rest = '\0';

		while (strchr("\r\n", password[strlen(password) - 1]))
			password[strlen(password) - 1] = '\0';

		TSDebug("kubernetes", "added user %s/%s", entry, password);
		hash_set(rp->rp_users, entry, strdup(password));
	}

	free(buf);
}

static void
rebuild_make_host(struct rebuild_ctx *ctx, remap_host_t *rh,
		  ingress_rule_t *rule)
{
size_t		 i;
char		*s;

	for (i = 0; i < rule->ir_npaths; i++) {
	ingress_path_t	*path = &rule->ir_paths[i];
	remap_path_t	*rp;
	service_t	*svc;

		svc = namespace_get_service(ctx->ns,
					    path->ip_service_name);
		if (svc == NULL)
			continue;

		TSDebug("kubernetes", "      path <%s> -> service <%s/%s>",
			path->ip_path, svc->sv_namespace, svc->sv_name);

		if (path->ip_path)
			rp = remap_host_new_path(rh, path->ip_path);
		else
			rp = remap_host_get_default_path(rh);

		if (rp == NULL)
			continue;

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

		/* ssl-redirect: if false, disable http->https redirect */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/ssl-redirect");
		if (s && !strcmp(s, "false"))
			rp->rp_no_ssl_redirect = 1;

		/*
		 * force-ssl-redirect: redirect http->https even if the
		 * Ingress doesn't have TLS configured.
		 */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/force-ssl-redirect");
		if (s && !strcmp(s, "true"))
			rp->rp_force_ssl_redirect = 1;

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
		 * Authentication.
		 */

		/* authentication type (basic/digest) */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/auth-type");
		if (s) {
			if (strcmp(s, "basic") == 0)
				rp->rp_auth_type = REMAP_AUTH_BASIC;
			else if (strcmp(s, "digest") == 0)
				rp->rp_auth_type = REMAP_AUTH_DIGEST;
		}

		/* authentication realm */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/auth-realm");
		if (s)
			rp->rp_auth_realm = strdup(s);

		/* authentication user database */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.kubernetes.io/auth-secret");
		if (s) {
		secret_t	*se;
			if ((se = namespace_get_secret(ctx->ns, s)) != NULL) {
				rp->rp_users = hash_new(127, free);
				remap_path_add_users(rp, se);
			}
		}

		/* authentication satisfy requirement (any, all) */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/auth-satisfy");
		if (s && !strcmp(s, "any"))
			rp->rp_auth_satisfy = REMAP_SATISFY_ANY;
		else
			rp->rp_auth_satisfy = REMAP_SATISFY_ALL;

		/* authentication address list */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/auth-address-list");
		if (s)
			rp->rp_auth_addr_list = remap_path_get_addresses(s);

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

	secret = namespace_get_secret(ctx->ns, itls->it_secret_name);
	if (!secret)
		TSDebug("kubernetes", "    warning: could not find secret [%s]",
			itls->it_secret_name);

	for (i = 0; i < itls->it_nhosts; i++) {
	const char	*hostname = itls->it_hosts[i];
	remap_host_t	*rh;
	char		*s;

		rh = remap_db_get_or_create_host(ctx->db, hostname);

		/* hsts-max-age: enable hsts. */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/hsts-max-age");
		if (s)
			rh->rh_hsts_max_age = atoi(s);

		/* hsts-include-subdomains: if set, hsts includes subdomains */
		s = hash_get(ctx->ingress->in_annotations,
			     "ingress.torchbox.com/hsts-include-subdomains");
		if (s && !strcmp(s, "true"))
			rh->rh_hsts_subdomains = 1;
		else
			rh->rh_hsts_subdomains = 0;

		if (secret) {
			if ((rh->rh_ctx = secret_make_ssl_ctx(secret)) == NULL) {
				TSDebug("kubernetes", "      %s: can't make ctx",
					hostname);
				continue;
			}
			TSDebug("kubernetes", "      %s: added with CTX[%p]",
				hostname, rh->rh_ctx);
		}
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
	remap_host_t	*rh;
	const char	*hostname = ing->in_rules[i].ir_host;

		TSDebug("kubernetes", "    hostname %s:", hostname);

		rh = remap_db_get_or_create_host(ctx->db, hostname);
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
rebuild_maps(struct state *state)
{
struct rebuild_ctx	ctx;

	TSMutexLock(state->cluster_lock);
	if (!state->changed) {
		TSDebug("kubernetes", "rebuild_maps: no changes");
		TSMutexUnlock(state->cluster_lock);
		return;
	}

	TSDebug("kubernetes", "rebuild_maps: running");
	ctx.db = remap_db_new();
	hash_foreach(state->cluster->cs_namespaces, rebuild_namespace, &ctx);

	state->changed = 0;
	TSMutexUnlock(state->cluster_lock);

	TSConfigSet(state->cfg_slot, ctx.db, (TSConfigDestroyFunc)remap_db_free);
}

/*
 * check_authn_basic: consider whether the request's authentication details
 * match the given route_path's configured user database.  if so, return 1;
 * otherwise return 0.
 */
int
check_authn_basic(TSHttpTxn txn, TSMBuffer reqp, TSMLoc hdrs,
		  const remap_path_t *rp)
{
TSMLoc		 auth_hdr = NULL;
int		 len, ret;
const char	*cs;

	auth_hdr = TSMimeHdrFieldFind(reqp, hdrs,
				      TS_MIME_FIELD_AUTHORIZATION,
				      TS_MIME_LEN_AUTHORIZATION);
	if (auth_hdr == NULL)
		return 0;

	cs = TSMimeHdrFieldValueStringGet(reqp, hdrs, auth_hdr, 0, &len);
	ret = auth_check_basic(cs, len, rp);
	TSHandleMLocRelease(reqp, hdrs, auth_hdr);

	return ret == 1 ? 1 : 0;
}

/*
 * check_authz_address: test whether the client IP address for this txn matches
 * the address list in the remap_path.
 */
int
check_authz_address(TSHttpTxn txn, const remap_path_t *rp)
{
const struct sockaddr	*addr;

	addr = TSHttpTxnClientAddrGet(txn);
	if (addr == NULL)
		return 0;

	return auth_check_address(addr, rp);
}

/*
 * check_authz: validate the request against the given remap_path's
 * authentication configuration.  One of the following values will be
 * returned:
 *
 * AUTHZ_PERMIT:
 * 	The request was successfully authentication and can proceed.
 *
 * AUTHZ_DENY_ADDRESS:
 * 	The request was denied because of the client's IP address; it should not
 * 	proceed and providing authentication will not help.  (Return code 403.)
 *
 * AUTHZ_DENY_AUTHN:
 * 	The request was denied because it was missing authentication details,
 * 	or the provided authentication was incorrect.  The request should not
 * 	proceed, but it may succeed if the client retries with valid
 * 	authentication.  (Return code 401.)
 */

#define	AUTHZ_PERMIT		1
#define	AUTHZ_DENY_ADDRESS	2
#define	AUTHZ_DENY_AUTHN	3

int
check_authz(TSHttpTxn txn, TSMBuffer reqp, TSMLoc hdrs, const remap_path_t *rp)
{
	if (rp->rp_auth_addr_list) {
		if (check_authz_address(txn, rp)) {
			if (rp->rp_auth_satisfy == REMAP_SATISFY_ANY) {
				TSDebug("kubernetes", "check_authz: permitted"
					" request because IP address matches"
					" and satisfy is ANY");
				return AUTHZ_PERMIT;
			}
		} else {
			if (rp->rp_auth_satisfy == REMAP_SATISFY_ALL)
				return AUTHZ_DENY_ADDRESS;
		}
	}

	switch (rp->rp_auth_type) {
	case REMAP_AUTH_NONE:
		TSDebug("kubernetes", "check_authz: permitted request because"
			" authentication is not configured");
		return AUTHZ_PERMIT;

	case REMAP_AUTH_BASIC:
		if (check_authn_basic(txn, reqp, hdrs, rp)) {
			TSDebug("kubernetes", "check_authz: permitted request"
				" because basic authentication succeeded");
			return AUTHZ_PERMIT;
		}
		break;

	case REMAP_AUTH_DIGEST:
		/* unimplemented */
		break;
	}

	return AUTHZ_DENY_AUTHN;
}

/*
 * Return 401 Unauthorized: the request was denied, but it might be permitted
 * if the client retries with an Authorization header field.
 */
static void
return_unauthorized(TSHttpTxn txnp, const remap_path_t *rp)
{
synth_t	*sy;
	sy = synth_new(401, "Authentication required");

	if (rp->rp_auth_type == REMAP_AUTH_BASIC)
		synth_add_header(sy, "WWW-Authenticate", "Basic realm=\"%s\"",
				 rp->rp_auth_realm ? rp->rp_auth_realm :
				   "Authentication required");

	synth_add_header(sy, "Content-Type", "text/plain; charset=UTF-8");
	synth_set_body(sy, "Authentication required.\r\n");
	synth_intercept(sy, txnp);
}

/*
 * Return 403 Forbidden: the request was denied, and it will never be allowed.
 */
static void
return_forbidden(TSHttpTxn txnp, const remap_path_t *rp)
{
synth_t	*sy;
	sy = synth_new(403, "Forbidden");

	synth_add_header(sy, "Content-Type", "text/plain; charset=UTF-8");
	synth_set_body(sy, "You do not have access to the requested resource.\r\n");
	synth_intercept(sy, txnp);
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
const remap_host_t	*rh;
const remap_path_t	*rp;
size_t			 poffs;
TSMBuffer		 reqp;
TSMLoc			 hdr_loc = NULL, url_loc = NULL, host_hdr = NULL;
TSHttpTxn		 txnp = (TSHttpTxn) edata;
TSConfig		 map_cfg = NULL;
const remap_db_t	*db;
struct state		*state = TSContDataGet(contn);

	map_cfg = TSConfigGet(state->cfg_slot);
	db = TSConfigDataGet(map_cfg);

	/* Not initialised yet? */
	if (!db)
		goto cleanup;


	/* Fetch the request and the URL. */
	TSHttpTxnClientReqGet(txnp, &reqp, &hdr_loc);
	TSHttpHdrUrlGet(reqp, hdr_loc, &url_loc);

	/*
	 * Fetch the host header, which could either be in the Host: header,
	 * or in the request path for a proxy-style request (GET http://).
	 * We need to handle both cases.
	 */
	host_hdr = TSMimeHdrFieldFind(reqp, hdr_loc,
				      TS_MIME_FIELD_HOST,
				      TS_MIME_LEN_HOST);
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
	if ((rh = remap_db_get_host(db, hbuf)) == NULL) {
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
	if ((rp = remap_host_find_path(rh, pbuf, &poffs)) == NULL) {
		TSDebug("kubernetes", "host <%s>, path <%s> not found",
			hbuf, pbuf);
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
	    ((rh->rh_ctx && !rp->rp_no_ssl_redirect)
	     || rp->rp_force_ssl_redirect)) {
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
		synth_add_header(sy, "Location", "%s", s);
		synth_add_header(sy, "Content-Type", "text/plain;charset=UTF-8");
		synth_set_body(sy, "The requested document has moved.\r\n");
		synth_intercept(sy, txnp);
		TSfree(s);

		goto cleanup;
	}

	/*
	 * Check authorization.  Do this after TLS redirect, so users aren't
	 * prompted to enter passwords over a plaintext connection.
	 */
	switch (check_authz(txnp, reqp, hdr_loc, rp)) {
	case AUTHZ_DENY_ADDRESS:
		return_forbidden(txnp, rp);
		goto cleanup;

	case AUTHZ_DENY_AUTHN:
		return_unauthorized(txnp, rp);
		goto cleanup;

	default:
		break;
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
	if (rh->rh_hsts_max_age)
		TSHttpTxnConfigIntSet(txnp, TS_CONFIG_SSL_HSTS_MAX_AGE,
				      rh->rh_hsts_max_age);
	TSHttpTxnConfigIntSet(txnp, TS_CONFIG_SSL_HSTS_INCLUDE_SUBDOMAINS,
			      rh->rh_hsts_subdomains);

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
		synth_add_header(sy, "Location", "%s", s);
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
	if (host_hdr)
		TSHandleMLocRelease(reqp, hdr_loc, host_hdr);
	if (url_loc)
		TSHandleMLocRelease(reqp, hdr_loc, url_loc);
	if (hdr_loc)
		TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdr_loc);
	free(pod_host);
	free(pbuf);
	free(hbuf);
	return TS_SUCCESS;
}
