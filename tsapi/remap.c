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
#include	<assert.h>

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
 * Called when the DNS lookup for an ExternalName has finished.
 */
static int
external_lookup(TSCont contn, TSEvent event, void *data)
{
TSHttpTxn	txnp = TSContDataGet(contn);

	assert(event == TS_EVENT_HOST_LOOKUP);

	if (data)
		TSHttpTxnServerAddrSet(txnp, data);

	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
	TSContDestroy(contn);
	return TS_SUCCESS;
}

/*
 * Build a remap_request to pass to remap_db from the TS request data.
 */
int
request_from_txn(TSHttpTxn txnp, remap_request_t *req)
{
TSMLoc		 hdrs, url, auth_hdr;
TSMBuffer	 reqp;
const char	*cs;
char		*s;
int		 len;

	bzero(req, sizeof(*req));

	/* Fetch the request and the URL. */
	TSHttpTxnClientReqGet(txnp, &reqp, &hdrs);
	TSHttpHdrUrlGet(reqp, hdrs, &url);

	/* scheme */
	if ((cs = TSUrlSchemeGet(reqp, url, &len)) != NULL)
		req->rr_proto = xstrndup(cs, len);

	/* host - if missing, ignore this request */
	if ((cs = TSHttpHdrHostGet(reqp, hdrs, &len)) != NULL) {
		req->rr_host = xstrndup(cs, len);

		/* remove port from host if present */
		if ((s = strchr(req->rr_host, ':')) != NULL)
			*s = '\0';
	}

	/* path */
	if ((cs = TSUrlPathGet(reqp, url, &len)) != NULL)
		req->rr_path = xstrndup(cs, len);

	/* query string */
	if ((cs = TSUrlHttpQueryGet(reqp, url, &len)) != NULL)
		req->rr_query = xstrndup(cs, len);

	/* client network address */
	req->rr_addr = TSHttpTxnClientAddrGet(txnp);

	/* Authorization header */
	auth_hdr = TSMimeHdrFieldFind(reqp, hdrs,
				      TS_MIME_FIELD_AUTHORIZATION,
				      TS_MIME_LEN_AUTHORIZATION);
	if (auth_hdr) {
		cs = TSMimeHdrFieldValueStringGet(reqp, hdrs, auth_hdr, 0,
						  &len);
		if (cs)
			req->rr_auth = xstrndup(cs, len);
		TSHandleMLocRelease(reqp, hdrs, auth_hdr);
	}

	TSHandleMLocRelease(reqp, hdrs, url);
	TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdrs);
	return 0;
}

/*
 * Build a Traffic Server URL as a TSMLoc from the given remap result.
 * Note that the URL doesn't have a host, because we use the Host: header
 * for that.
 */
TSMLoc
url_from_remap_result(TSHttpTxn txn, remap_request_t *req,
		      remap_result_t *res)
{
TSMBuffer	reqp;
TSMLoc		hdrs, newurl;

	TSHttpTxnClientReqGet(txn, &reqp, &hdrs);

	TSUrlCreate(reqp, &newurl);
	TSUrlSchemeSet(reqp, newurl, res->rz_proto, -1);

	if (res->rz_urlpath)
		TSUrlPathSet(reqp, newurl, res->rz_urlpath, -1);
	else
		TSUrlPathSet(reqp, newurl, req->rr_path, -1);

	if (res->rz_query)
		TSUrlHttpParamsSet(reqp, newurl, res->rz_query, -1);
	else
		TSUrlHttpParamsSet(reqp, newurl, req->rr_query, -1);

	TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdrs);
	return newurl;
}

/*
 * Set or replace the Host header field on the request.
 */
void
set_host_field(TSHttpTxn txnp, const char *host)
{
TSMBuffer	reqp;
TSMLoc		hdrs, host_hdr;

	TSHttpTxnClientReqGet(txnp, &reqp, &hdrs);

	/*
	 * Set the host header.
	 */
	if ((host_hdr = TSMimeHdrFieldFind(reqp, hdrs, "Host", 4)) != NULL) {
		TSMimeHdrFieldRemove(reqp, hdrs, host_hdr);
		TSHandleMLocRelease(reqp, hdrs, host_hdr);
	}

	TSMimeHdrFieldCreateNamed(reqp, hdrs, "Host", 4, &host_hdr);
	TSMimeHdrFieldValueStringInsert(reqp, hdrs, host_hdr, 0, host, strlen(host));
	TSMimeHdrFieldAppend(reqp, hdrs, host_hdr);

	TSHandleMLocRelease(reqp, hdrs, host_hdr);
	TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdrs);
}

void
add_xfp(TSHttpTxn txn)
{
TSMBuffer	reqp;
TSMLoc		hdrs, xfp;

	TSHttpTxnClientReqGet(txn, &reqp, &hdrs);

	/* Remove any existing X-Forwarded-Proto header */
	xfp = TSMimeHdrFieldFind(reqp, hdrs,
		      REMAP_MIME_FIELD_X_FORWARDED_PROTO,
		      REMAP_MIME_FIELD_X_FORWARDED_PROTO_LEN);
	if (xfp != TS_NULL_MLOC) {
		TSMimeHdrFieldRemove(reqp, hdrs, xfp);
		TSHandleMLocRelease(reqp, hdrs, xfp);
	}

	TSMimeHdrFieldCreateNamed(reqp, hdrs,
				REMAP_MIME_FIELD_X_FORWARDED_PROTO,
				REMAP_MIME_FIELD_X_FORWARDED_PROTO_LEN,
				&xfp);

	if (TSHttpTxnClientProtocolStackContains(txn, "tls"))
		TSMimeHdrFieldValueStringInsert(reqp, hdrs, xfp, 0,
					     "https", 5);
	else
		TSMimeHdrFieldValueStringInsert(reqp, hdrs, xfp, 0,
					     "http", 4);

	TSMimeHdrFieldAppend(reqp, hdrs, xfp);

	TSHandleMLocRelease(reqp, hdrs, xfp);
	TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdrs);
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
TSMLoc			 newurl;
TSHttpTxn		 txnp = (TSHttpTxn) edata;
TSConfig		 map_cfg = NULL;
const remap_db_t	*db;
struct state		*state = TSContDataGet(contn);
remap_request_t		 req;
remap_result_t		 res;
synth_t			*sy;
struct sockaddr_in	 addr;
int			 reenable = 1;

	map_cfg = TSConfigGet(state->cfg_slot);
	db = TSConfigDataGet(map_cfg);

	/* Not initialised yet? */
	if (!db) {
		TSDebug("kubernetes", "handle_remap: no database");
		goto cleanup;
	}

	/* Create a remap_request from the TS request */
	if (request_from_txn(txnp, &req) != 0)
		goto cleanup;

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

	if ((newurl = url_from_remap_result(txnp, &req, &res)) == NULL)
		goto cleanup;

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
	 * Usually, we want to preserve the request host header so the backend
	 * can use it.  If preserve-host is set to false on the Ingress, then
	 * we instead replace any host header in the request with the backend
	 * host.
	 */
	if (res.rz_path->rp_preserve_host)
		set_host_field(txnp, req.rr_host);
	else
		set_host_field(txnp, res.rz_target->rt_host);

	/* Add an X-Forwarded-Proto header, if configured */
	if (state->config->co_xfp)
		add_xfp(txnp);

	/*
	 * We already remapped this request, so skip any further remapping.
	 * This also prevents TS from failing the request if remap_required
	 * is set.
	 */
	TSSkipRemappingSet(txnp, 1);

	/*
	 * If the target is an IP address (the usual case) we can pass it
	 * to TS directly.
	 */
	bzero(&addr, sizeof(addr));
	if (inet_pton(AF_INET, res.rz_target->rt_host, &addr.sin_addr) == 1) {
		addr.sin_family = AF_INET;
		addr.sin_port = htons(res.rz_target->rt_port);
		TSHttpTxnServerAddrSet(txnp, (struct sockaddr *) &addr);
	} else {
	TSCont	ext_cont;

		/*
		 * We have a DNS name, so we need to do a host lookup to get the
		 * IP address.
		 */
		if ((ext_cont = TSContCreate(external_lookup,
					     TSMutexCreate())) == NULL) {
			/* Well, that's unfortunate. */
			TSDebug("kubernetes", "[%s] cannot create continuation",
				res.rz_target->rt_host);
			goto cleanup;
		}

		TSContDataSet(ext_cont, txnp);
		TSHostLookup(ext_cont, res.rz_target->rt_host,
			     strlen(res.rz_target->rt_host));
		TSDebug("kubernetes", "[%s]: starting external name lookup",
			res.rz_target->rt_host);
		reenable = 0;
	}

cleanup:
	TSConfigRelease(state->cfg_slot, map_cfg);

	remap_request_free(&req);
	remap_result_free(&res);

	if (reenable)
		TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

	return TS_SUCCESS;
}
