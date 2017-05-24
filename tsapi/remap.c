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
	db = remap_db_from_cluster(state->config, state->cluster);
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

static char *
xstrndup(const char *s, size_t n)
{
char	*ret;
	if ((ret = malloc(n + 1)) == NULL)
		return NULL;
	bcopy(s, ret, n);
	ret[n] = '\0';
	return ret;
}

/*
 * handle_remap: called in READ_REQUEST_HDR_HOOK.  Match the incoming request
 * to an Ingress path (remap_path), apply any configurations from annotations,
 * and either set the host to proxy the request to the backend, or return
 * our own error or redirect response.
 */
int
handle_remap(TSCont contn, TSEvent event, void *edata)
{
int			 len;
char			*requrl = NULL;
const char		*cs;
char			*hbuf = NULL, *pbuf = NULL, *s;
TSMBuffer		 reqp;
TSMLoc			 hdr_loc = NULL, url_loc = NULL, host_hdr = NULL,
			 auth_hdr = NULL;
TSHttpTxn		 txnp = (TSHttpTxn) edata;
TSConfig		 map_cfg = NULL;
const remap_db_t	*db;
struct state		*state = TSContDataGet(contn);
remap_request_t		 req;
remap_result_t		 res;
synth_t			*sy;

	map_cfg = TSConfigGet(state->cfg_slot);
	db = TSConfigDataGet(map_cfg);

	/* Not initialised yet? */
	if (!db)
		goto cleanup;

	/* Fetch the request and the URL. */
	TSHttpTxnClientReqGet(txnp, &reqp, &hdr_loc);
	TSHttpHdrUrlGet(reqp, hdr_loc, &url_loc);

	/*
	 * Construct a remap_request from the TS request.
	 */
	bzero(&req, sizeof(req));

	/* scheme */
	if ((cs = TSUrlSchemeGet(reqp, url_loc, &len)) != NULL)
		req.rr_proto = xstrndup(cs, len);

	/* host */
	host_hdr = TSMimeHdrFieldFind(reqp, hdr_loc, "Host", 4);

	/*
	 * If the request doesn't have a Host, copy it from the URL. If the URL
	 * doesn't have one either, give up.
	 */
	if (!host_hdr) {
		if ((cs = TSHttpHdrHostGet(reqp, hdr_loc, &len)) == NULL)
			goto cleanup;

		TSMimeHdrFieldCreateNamed(reqp, hdr_loc, "Host", 4, &host_hdr);
		TSMimeHdrFieldValueStringSet(reqp, hdr_loc, host_hdr, 0, cs, len);
	}

	cs = TSMimeHdrFieldValueStringGet(reqp, hdr_loc, host_hdr, 0, &len);
	req.rr_host = xstrndup(cs, len);

	/* remove port from URL if present */
	if ((s = strchr(req.rr_host, ':')) != NULL)
		*s = '\0';

	/* path */
	if ((cs = TSUrlPathGet(reqp, url_loc, &len)) != NULL)
		req.rr_path = xstrndup(cs, len);

	/* query string */
	if ((cs = TSUrlHttpQueryGet(reqp, url_loc, &len)) != NULL)
		req.rr_query = xstrndup(cs, len);

	/* client network address */
	req.rr_addr = TSHttpTxnClientAddrGet(txnp);

	/* Authorization header */
	auth_hdr = TSMimeHdrFieldFind(reqp, hdr_loc,
				      TS_MIME_FIELD_AUTHORIZATION,
				      TS_MIME_LEN_AUTHORIZATION);
	if (auth_hdr) {
		cs = TSMimeHdrFieldValueStringGet(reqp, hdr_loc, auth_hdr, 0,
						  &len);
		if (cs)
			req.rr_auth = xstrndup(cs, len);
	}

	/* Do the remap */
	switch (remap_run(db, &req, &res)) {
	case RR_REDIRECT:
		sy = synth_new(301, "Moved");
		synth_add_header(sy, "Location", "%s", res.rz_location);
		synth_add_header(sy, "Content-Type", "text/plain;charset=UTF-8");
		synth_set_body(sy, "The requested document has moved.\r\n");
		synth_intercept(sy, txnp);
		goto cleanup;

		/* client errors */
	case RR_ERR_INVALID_HOST:
	case RR_ERR_INVALID_PROTOCOL:
		sy = synth_new(400, "Bad request");
		synth_add_header(sy, "Content-Type", "text/plain;charset=UTF-8");
		synth_set_body(sy, "The server could not undestand this request.\r\n");
		synth_intercept(sy, txnp);
		goto cleanup;

		/* not found */
	case RR_ERR_NO_HOST:
	case RR_ERR_NO_PATH:
		/*
		 * Don't return an error here; let other plugins (like
		 * healthchecks) handle the request.
		 */
		goto cleanup;

		/* no backend */
	case RR_ERR_NO_BACKEND:
		sy = synth_new(503, "Service unavailable");
		synth_add_header(sy, "Content-Type", "text/plain;charset=UTF-8");
		synth_set_body(sy, "No backend is available to service this"
				   " request.\r\n");
		synth_intercept(sy, txnp);
		goto cleanup;

	case RR_ERR_FORBIDDEN:
		sy = synth_new(403, "Forbidden");
		synth_add_header(sy, "Content-Type", "text/plain;charset=UTF-8");
		synth_set_body(sy, "Access denied.\r\n");
		synth_intercept(sy, txnp);
		goto cleanup;

	case RR_ERR_UNAUTHORIZED:
		sy = synth_new(401, "Unauthorized");
		synth_add_header(sy, "Content-Type", "text/plain;charset=UTF-8");
		synth_set_body(sy, "Unauthorized.\r\n");
		synth_intercept(sy, txnp);
		goto cleanup;

	case RR_OK:
		break;

	default:
		goto cleanup;
	}

	/*
	 * The remap succeeded, so we need to set the new backend
	 * protocol, host:port and other request configuration.
	 */

	/* set URL path if different */
	if (res.rz_urlpath)
		TSUrlPathSet(reqp, url_loc, res.rz_urlpath,
			     strlen(res.rz_urlpath));

	/* follow redirects if configured on the Ingress.  */
	if (res.rz_path->rp_follow_redirects) {
		TSHttpTxnConfigIntSet(txnp,
				TS_CONFIG_HTTP_ENABLE_REDIRECTION, 1);
		TSHttpTxnConfigIntSet(txnp,
				TS_CONFIG_HTTP_REDIRECT_USE_ORIG_CACHE_KEY, 1);
	}

	/*
	 * Set cache generation if it's set on the Ingress.  If it's not set,
	 * just set it to zero.
	 */
	TSHttpTxnConfigIntSet(txnp, TS_CONFIG_HTTP_CACHE_GENERATION,
			      res.rz_path->rp_cache_gen);

	/*
	 * Enable caching, unless it's been cached on the Ingress.
	 */
	TSHttpTxnConfigIntSet(txnp, TS_CONFIG_HTTP_CACHE_HTTP,
			      res.rz_path->rp_cache);

	/*
	 * Send HSTS headers.
	 */
	if (res.rz_host->rh_hsts_max_age)
		TSHttpTxnConfigIntSet(txnp, TS_CONFIG_SSL_HSTS_MAX_AGE,
				      res.rz_host->rh_hsts_max_age);
	TSHttpTxnConfigIntSet(txnp, TS_CONFIG_SSL_HSTS_INCLUDE_SUBDOMAINS,
			      res.rz_host->rh_hsts_subdomains);


	/*
	 * Set the backend for this request.  This is the actual request
	 * remapping.
	 */
	if (TSUrlHostSet(reqp, url_loc, res.rz_target->rt_host,
			 strlen(res.rz_target->rt_host)) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set request host", requrl);
		goto cleanup;
	}

	if (TSUrlPortSet(reqp, url_loc, res.rz_target->rt_port) != TS_SUCCESS) {
		TSError("[kubernetes] <%s>: could not set request port", requrl);
		goto cleanup;
	}

	/* set the backend URL scheme */
	TSUrlSchemeSet(reqp, url_loc, res.rz_proto, strlen(res.rz_proto));

	/*
	 * Usually, we want to preserve the request host header so the backend
	 * can use it.  If preserve-host is set to false on the Ingress, then
	 * we instead replace any host header in the request with the backend
	 * host.
	 */
	if (res.rz_path->rp_preserve_host) {
		TSMimeHdrFieldValueStringSet(reqp, hdr_loc, host_hdr, 0,
					     req.rr_host, strlen(req.rr_host));
	} else {
		TSHttpTxnConfigIntSet(txnp, TS_CONFIG_URL_REMAP_PRISTINE_HOST_HDR, 0);
		TSMimeHdrFieldValueStringSet(reqp, hdr_loc, host_hdr, 0,
					     res.rz_target->rt_host,
					     strlen(res.rz_target->rt_host));
	}

	if (state->config->co_xfp) {
	TSMLoc	xfp;
		/* Remove any existing X-Forwarded-Proto header */
		xfp = TSMimeHdrFieldFind(reqp, hdr_loc,
			      REMAP_MIME_FIELD_X_FORWARDED_PROTO,
			      REMAP_MIME_FIELD_X_FORWARDED_PROTO_LEN);
		if (xfp != TS_NULL_MLOC) {
			TSMimeHdrFieldRemove(reqp, hdr_loc, xfp);
			TSMimeHdrFieldValuesClear(reqp, hdr_loc, xfp);
		} else {
			TSMimeHdrFieldCreateNamed(reqp, hdr_loc,
					REMAP_MIME_FIELD_X_FORWARDED_PROTO,
					REMAP_MIME_FIELD_X_FORWARDED_PROTO_LEN,
					&xfp);
		}

		if (TSHttpTxnClientProtocolStackContains(txnp, "tls"))
			TSMimeHdrFieldValueStringInsert(reqp, hdr_loc, xfp, 0,
						     "https", 5);
		else
			TSMimeHdrFieldValueStringInsert(reqp, hdr_loc, xfp, 0,
						     "http", 4);

		TSMimeHdrFieldAppend(reqp, hdr_loc, xfp);
		TSHandleMLocRelease(reqp, hdr_loc, xfp);
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
