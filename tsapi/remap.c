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

void
rebuild_maps(struct state *state)
{
remap_db_t	*db;

	TSMutexLock(state->cluster_lock);
	if (!state->changed) {
		TSDebug("kubernetes", "rebuild_maps: no changes");
		TSMutexUnlock(state->cluster_lock);
		return;
	}

	TSDebug("kubernetes", "rebuild_maps: running");
	db = remap_db_from_cluster(state->cluster);
	state->changed = 0;
	TSMutexUnlock(state->cluster_lock);

	TSConfigSet(state->cfg_slot, db, (TSConfigDestroyFunc)remap_db_free);
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
int			 len;
char			*requrl = NULL;
const char		*cs;
char			*hbuf = NULL, *pbuf = NULL, *s;
const remap_host_t	*rh;
const remap_path_t	*rp;
const remap_target_t	*rt;
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
	rt = remap_path_pick_target(rp);
	TSDebug("kubernetes", "remapped to %s:%d", rt->rt_host, rt->rt_port);

	/*
	 * Usually, we want to preserve the request host header so the backend
	 * can use it.  If preserve-host is set on the Ingress, then we instead
	 * replace any host header in the request with the backend host.
	 */
	if (!rp->rp_preserve_host) {
		TSHttpTxnConfigIntSet(txnp, TS_CONFIG_URL_REMAP_PRISTINE_HOST_HDR, 0);
		if (host_hdr)
			TSMimeHdrFieldValueStringSet(reqp, hdr_loc, host_hdr, 0,
						     rt->rt_host,
						     strlen(rt->rt_host));
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
	 * Set the backend for this request.  This is the actual request
	 * remapping.
	 */
	if (TSUrlHostSet(reqp, url_loc, rt->rt_host,
			 strlen(rt->rt_host)) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set request host", requrl);
		goto cleanup;
	}

	if (TSUrlPortSet(reqp, url_loc, rt->rt_port) != TS_SUCCESS) {
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
	free(pbuf);
	free(hbuf);
	return TS_SUCCESS;
}
