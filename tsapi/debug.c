/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */
/*
 * debug.c: transaction debug log functions.
 */

#include	<ts/ts.h>

#include	"plugin.h"

static void
debug_dump_header(TSHttpTxn txn, TSMBuffer buf, TSMLoc hdr)
{
	for (int i = 0, end = TSMimeHdrFieldsCount(buf, hdr); i < end; ++i) {
	const char	*hdrs, *vals;
	int		 hdrlen, vallen;
	TSMLoc		 field = TSMimeHdrFieldGet(buf, hdr, i);

		hdrs = TSMimeHdrFieldNameGet(buf, hdr, field, &hdrlen);

		for (int j = 0, jend = TSMimeHdrFieldValuesCount(buf, hdr, field);
		     j < jend; ++j) {

			vals = TSMimeHdrFieldValueStringGet(buf, hdr, field,
							    j, &vallen);
			TSError("[kubernetes] txn %p: [%d/%d] %.*s: %.*s",
				txn, j+1, jend, hdrlen, hdrs, vallen, vals);
		}

		TSHandleMLocRelease(buf, hdr, field);
	}
}

void
debug_log_read_request_hdr(TSHttpTxn txn)
{
TSMBuffer	 req;
TSMLoc		 hdr, url;
const char	*cs;
int		 i, version;

	if (TSHttpTxnClientReqGet(txn, &req, &hdr) != TS_SUCCESS) {
		TSError("kubernetes: debug_log_request: can't get req?");
		return;
	}

	version = TSHttpHdrVersionGet(req, hdr);
	cs = TSHttpHdrMethodGet(req, hdr, &i);
	TSError("[kubernetes] txn %p: read request method %.*s version %d.%d",
		txn, i, cs, TS_HTTP_MAJOR(version), TS_HTTP_MINOR(version));

	TSHttpHdrUrlGet(req, hdr, &url);
	cs = TSUrlStringGet(req, url, &i);
	TSError("[kubernetes] txn %p: req url: %.*s", txn, i, cs);
	TSfree(cs);

	TSHandleMLocRelease(req, hdr, url);

	TSError("[kubernetes] txn %p: --- dump request header ---", txn);
	debug_dump_header(txn, req, hdr);
	TSHandleMLocRelease(req, TS_NULL_MLOC, hdr);
	TSError("[kubernetes] txn %p: --- end request header ---", txn);
}

void
debug_log_cache_lookup_complete(TSHttpTxn txn)
{
TSMBuffer	 req;
TSMLoc		 hdr;
TSMgmtInt	 cache_gen = 0;
int		 status;
static const char *const status_names[] = {
	"miss", "hit-stale", "hit-fresh", "skipped", "unknown"
};

	TSHttpTxnConfigIntGet(txn, TS_CONFIG_HTTP_CACHE_GENERATION, &cache_gen);
	TSError("[kubernetes] txn %p: cache lookup complete, generation %ld",
		txn, (long) cache_gen);

	TSHttpTxnCacheLookupStatusGet(txn, &status);
	if (status < 0 || status > 4)
		TSError("[kubernetes] txn %p: cache status %d?", txn, status);
	else
		TSError("[kubernetes] txn %p: cache status %s", txn,
			status_names[status]);

	if (status != 2)
		return;

	if (TSHttpTxnCachedRespGet(txn, &req, &hdr) != TS_SUCCESS) {
		TSError("kubernetes: debug_log_cache_looked_complete: "
			"can't get resp?");
		return;
	}

	TSError("[kubernetes] txn %p: --- dump cached header ---", txn);
	debug_dump_header(txn, req, hdr);
	TSHandleMLocRelease(req, TS_NULL_MLOC, hdr);
	TSError("[kubernetes] txn %p: --- end cached header ---", txn);
}

void
debug_log_send_request_hdr(TSHttpTxn txn)
{
TSMBuffer	 req;
TSMLoc		 hdr, url;
const char	*cs;
int		 i;

	if (TSHttpTxnServerReqGet(txn, &req, &hdr) != TS_SUCCESS) {
		TSError("kubernetes: debug_log_send_request_hdr: "
			"can't get req?");
		return;
	}

	TSHttpHdrUrlGet(req, hdr, &url);
	cs = TSUrlStringGet(req, url, &i);
	TSError("[kubernetes] txn %p: origin send request url %.*s", txn, i, cs);
	TSfree(cs);
	TSHandleMLocRelease(req, hdr, url);

	TSError("[kubernetes] txn %p: --- dump origin request header ---", txn);
	debug_dump_header(txn, req, hdr);
	TSHandleMLocRelease(req, TS_NULL_MLOC, hdr);
	TSError("[kubernetes] txn %p: --- end origin request header ---", txn);
}

void
debug_log_read_response_hdr(TSHttpTxn txn)
{
TSMBuffer	 resp;
TSMLoc		 hdr;
const char	*cs;
int		 i, status;

	if (TSHttpTxnServerRespGet(txn, &resp, &hdr) != TS_SUCCESS) {
		TSError("kubernetes: debug_log_read_response_hdr: "
			"can't get resp?");
		return;
	}

	status = TSHttpHdrStatusGet(resp, hdr);
	cs = TSHttpHdrReasonGet(resp, hdr, &i);
	TSError("[kubernetes] txn %p: origin read response status %d reason %.*s",
		txn, status, i, cs);

	TSError("[kubernetes] txn %p: --- dump origin response header ---", txn);
	debug_dump_header(txn, resp, hdr);
	TSHandleMLocRelease(resp, TS_NULL_MLOC, hdr);
	TSError("[kubernetes] txn %p: --- end origin response header ---", txn);
}

void
debug_log_send_response_hdr(TSHttpTxn txn)
{
TSMBuffer	 resp;
TSMLoc		 hdr;
const char	*cs;
int		 i, status;

	if (TSHttpTxnClientRespGet(txn, &resp, &hdr) != TS_SUCCESS) {
		TSError("kubernetes: debug_log_send_response_hdr: "
			"can't get resp?");
		return;
	}

	status = TSHttpHdrStatusGet(resp, hdr);
	cs = TSHttpHdrReasonGet(resp, hdr, &i);
	TSError("[kubernetes] txn %p: client send response status %d reason %.*s",
		txn, status, i, cs);

	TSError("[kubernetes] txn %p: --- dump client response header ---", txn);
	debug_dump_header(txn, resp, hdr);
	TSHandleMLocRelease(resp, TS_NULL_MLOC, hdr);
	TSError("[kubernetes] txn %p: --- end client response header ---", txn);
}
