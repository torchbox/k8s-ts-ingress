/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
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
#include	"plugin.h"
#include	"tls.h"

int
handle_tls(TSCont contn, TSEvent evt, void *edata)
{
TSVConn			 ssl_vc = edata;
SSL			*ssl = (SSL *)TSVConnSSLConnectionGet(ssl_vc);
const char		*host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
const remap_host_t	*rh;
TSConfig		 db_cfg = NULL;
const remap_db_t	*db;
struct state		*state = TSContDataGet(contn);

	/* Host can sometimes be null; do nothing in that case. */
	if (!host)
		goto cleanup;

	TSDebug("kubernetes_tls", "doing SNI map for [%s]", host);

	db_cfg = TSConfigGet(state->cfg_slot);
	db = TSConfigDataGet(db_cfg);

	/* Not initialised yet? */
	if (!db)
		goto cleanup;

	if ((rh = remap_db_get_host(db, host)) == NULL) {
		TSDebug("kubernetes", "[%s] TLS SNI: host not found", host);
		goto cleanup;
	}

	if (!rh->rh_ctx) {
		TSDebug("kubernetes", "[%s] TLS SNI: host found, but not ctx",
			host);
		goto cleanup;
	}

	SSL_set_SSL_CTX(ssl, rh->rh_ctx);
	TSVConnReenable(ssl_vc);

cleanup:
	if (db_cfg)
		TSConfigRelease(state->cfg_slot, db_cfg);
	return TS_SUCCESS;
}
