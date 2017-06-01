/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<ctype.h>
#include	<string.h>
#include	<assert.h>

#include	<ts/ts.h>
#include	<zlib.h>

#include	"brotli/encode.h"
#include	"remap.h"

#define	COMP_NONE	0
#define	COMP_GZIP	1
#define	COMP_BROTLI	2

struct comp_state;

typedef void (*comp_init_callback) (struct comp_state *);
typedef int64_t (*comp_produce_callback) (struct comp_state *,
					  unsigned const char *, size_t);
typedef int64_t (*comp_finish_callback) (struct comp_state *);
typedef void (*comp_free_callback) (struct comp_state *);

typedef struct comp_state {
	TSHttpTxn	cs_txn;
	int		cs_type;
	hash_t		cs_types;

	/* The VIO that's writing to us */
	TSVIO			cs_input_vio;
	TSIOBufferReader	cs_input_reader;

	/* The VIO we're writing to */
	int64_t			cs_output_len;
	TSIOBuffer		cs_output_buffer;
	TSIOBufferReader	cs_output_reader;
	TSVIO			cs_output_vio;
	TSCont			cs_output_conn;

	int			cs_done_init:1;

	/* callbacks */
	comp_init_callback	cs_init;
	comp_produce_callback	cs_produce;
	comp_finish_callback	cs_finish;
	comp_free_callback	cs_free;

	/* compression state */
	union {
		z_stream		 cs_zstream;
		BrotliEncoderState	*cs_brotli;
	};
} comp_state_t;

/* gzip */
void	gzip_init(comp_state_t *);
int64_t	gzip_produce(comp_state_t *, unsigned const char *input, size_t inlen);
int64_t	gzip_finish(comp_state_t *);
void	gzip_free(comp_state_t *);

/* brotli */
void	br_init(comp_state_t *);
int64_t	br_produce(comp_state_t *, unsigned const char *input, size_t inlen);
int64_t	br_finish(comp_state_t *);
void	br_free(comp_state_t *);

static void
comp_state_free(comp_state_t *cs)
{
	if (cs->cs_done_init)
		cs->cs_free(cs);
	hash_free(cs->cs_types);
	free(cs);
}

void
br_init(comp_state_t *state)
{
	state->cs_brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);
	BrotliEncoderSetParameter(state->cs_brotli, BROTLI_PARAM_QUALITY, 2);
}

void
br_free(comp_state_t *cs)
{
	BrotliEncoderDestroyInstance(cs->cs_brotli);
}

int64_t
br_produce(comp_state_t *state, unsigned const char *inbuf, size_t inlen)
{
int64_t		 written = 0;
TSIOBufferBlock	 oblk;
char		*obuf;
int64_t		 olen = 0;
int		 ret;
size_t		 avail_in, avail_out;
const uint8_t	*next_in;
uint8_t		*next_out;

	avail_in = inlen;
	next_in = (const uint8_t *) inbuf;

	while (avail_in) {
		oblk = TSIOBufferStart(state->cs_output_buffer);
		obuf = TSIOBufferBlockWriteStart(oblk, &olen);

		TSDebug("kubernetes", "br_produce: avail_in=%d, "
			"written=%ld, we can write %d",
			(int) avail_in,
			(long) written, (int) olen);

		avail_out = olen;
		next_out = (uint8_t *)obuf;

		ret = BrotliEncoderCompressStream(state->cs_brotli,
				BROTLI_OPERATION_PROCESS,
				&avail_in, &next_in,
				&avail_out, &next_out, NULL);

		written += (olen - avail_out);
		TSIOBufferProduce(state->cs_output_buffer,
				(olen - avail_out));

		TSDebug("kubernetes", "br_produce: ret %d, wrote %d",
			ret, (int) (olen - avail_out));
	}

	return written;
}

int64_t
br_finish(comp_state_t *state)
{
int64_t		written = 0;
int		ret;
size_t		avail_in = 0, avail_out;
const uint8_t	*next_in = NULL;
uint8_t		*next_out;

	do {
	TSIOBufferBlock	 oblk;
	char		*obuf;
	int64_t		 olen = 0;

		oblk = TSIOBufferStart(state->cs_output_buffer);
		obuf = TSIOBufferBlockWriteStart(oblk, &olen);

		TSDebug("kubernetes", "br_finish: we can write %d",
			(int) olen);

		avail_out = olen;
		next_out = (unsigned char *)obuf;

		ret = BrotliEncoderCompressStream(state->cs_brotli,
				BROTLI_OPERATION_FINISH,
				&avail_in, &next_in,
				&avail_out, &next_out, NULL);

		written += (olen - avail_out);
		TSIOBufferProduce(state->cs_output_buffer,
				(olen - avail_out));

		TSDebug("kubernetes", "br_finish: wrote %d",
			(int) (olen - avail_out));
	} while (BrotliEncoderHasMoreOutput(state->cs_brotli));

	return written;
}

void
gzip_init(comp_state_t *state)
{
	bzero(&state->cs_zstream, sizeof(state->cs_zstream));
	deflateInit2(&state->cs_zstream, 3, Z_DEFLATED, 15 + 16, 8,
		    Z_DEFAULT_STRATEGY);
}

void
gzip_free(comp_state_t *state)
{
	deflateEnd(&state->cs_zstream);
}

int64_t
gzip_produce(comp_state_t *state, unsigned const char *inbuf, size_t inlen)
{
int64_t		 written = 0;
TSIOBufferBlock	 oblk;
char		*obuf;
int64_t		 olen = 0;
int		 ret;

	state->cs_zstream.avail_in = inlen;
	state->cs_zstream.next_in = (unsigned char *)inbuf;

	do {
		oblk = TSIOBufferStart(state->cs_output_buffer);
		obuf = TSIOBufferBlockWriteStart(oblk, &olen);

		TSDebug("kubernetes", "gzip_produce: avail_in=%d, "
			"written=%ld, we can write %d",
			(int) state->cs_zstream.avail_in,
			(long) written, (int) olen);

		state->cs_zstream.avail_out = olen;
		state->cs_zstream.next_out = (unsigned char *)obuf;

		ret = deflate(&state->cs_zstream, Z_NO_FLUSH);
		written += (olen - state->cs_zstream.avail_out);
		TSIOBufferProduce(state->cs_output_buffer,
				(olen - state->cs_zstream.avail_out));

		TSDebug("kubernetes", "compress_do: wrote %d",
			(int) (olen - state->cs_zstream.avail_out));
	} while (ret == Z_OK);

	return written;
}

int64_t
gzip_finish(comp_state_t *state)
{
int64_t	written = 0;
int	ret;

	state->cs_zstream.avail_in = 0;

	do {
	TSIOBufferBlock	 oblk;
	char		*obuf;
	int64_t		 olen = 0;

		oblk = TSIOBufferStart(state->cs_output_buffer);
		obuf = TSIOBufferBlockWriteStart(oblk, &olen);

		TSDebug("kubernetes", "gzip_finish: we can write %d",
			(int) olen);

		state->cs_zstream.avail_out = olen;
		state->cs_zstream.next_out = (unsigned char *)obuf;

		ret = deflate(&state->cs_zstream, Z_FINISH);
		written += (olen - state->cs_zstream.avail_out);
		TSIOBufferProduce(state->cs_output_buffer,
				(olen - state->cs_zstream.avail_out));

		TSDebug("kubernetes", "gzip_finish: wrote %d",
			(int) (olen - state->cs_zstream.avail_out));
	} while (ret == Z_OK || ret == Z_BUF_ERROR);

	return written;
}

/*
 * Check whether compression can be enabled for the given accept-encoding hdr.
 */
static int
request_can_compress(TSMBuffer reqp, TSMLoc hdr)
{
const char	*cs;
int		 len;
TSMLoc		 aenc;
int		 has_gzip = 0, has_br = 0;

	aenc = TSMimeHdrFieldFind(reqp, hdr, "Accept-Encoding", -1);
	if (!aenc)
		return COMP_NONE;

	for (int i = 1, end = TSMimeHdrFieldValuesCount(reqp, hdr, aenc);
	     i <= end; ++i) {

		cs = TSMimeHdrFieldValueStringGet(reqp, hdr, aenc, end - i, &len);

		if ((len == 4 && memcmp(cs, "gzip", 4) == 0)
		    || (len >= 4 && memcmp(cs, "gzip;", 5) == 0))
			has_gzip = 1;

		if ((len == 2 && memcmp(cs, "br", 2) == 0)
		    || (len >= 2 && memcmp(cs, "br;", 2) == 0))
			has_br = 1;
	}

	TSHandleMLocRelease(reqp, hdr, aenc);

	/*
	 * We ignore the browser's preference here and just prefer br if
	 * available.   Most browsers don't seem to send qvalues in
	 * AE anyway.
	 */
	if (has_br)
		return COMP_BROTLI;
	if (has_gzip)
		return COMP_GZIP;
	return COMP_NONE;
}

/*
 * Determine whether the response can be compressed.  It cannot if it already
 * has a content-encoding.
 */
static int
response_can_compress(comp_state_t *state, TSMBuffer resp, TSMLoc hdr)
{
TSMLoc		 field;
int		 len;
char		*s, *p;
const char	*cs;

	/* 
	 * If the response already has a Content-Encoding header, it's not
	 * cacheable.
	 */
	field = TSMimeHdrFieldFind(resp, hdr, "Content-Encoding", -1);
	if (field) {
		TSHandleMLocRelease(resp, hdr, field);
		return 0;
	}

	/*
	 * See if the content type is on our list of allowed types.
	 */
	field = TSMimeHdrFieldFind(resp, hdr, "Content-Type", -1);
	if (field == TS_NULL_MLOC) {
		TSDebug("kubernetes", "response_can_compress: no content-type");
		return 0;
	}

	cs = TSMimeHdrFieldValueStringGet(resp, hdr, field, 0, &len);
	if (cs == NULL) {
		TSDebug("kubernetes", "compress_hook: content-type header, but no values");
		TSHandleMLocRelease(resp, hdr, field);
		return 0;
	}

	s = malloc(len + 1);
	bcopy(cs, s, len);
	if ((p = memchr(s, ';', len)) != NULL)
		*p = '\0';
	else
		s[len] = '\0';

	TSHandleMLocRelease(resp, hdr, field);

	if (hash_get(state->cs_types, s) == NULL) {
		TSDebug("kubernetes", "response_can_compress: content-type [%s]"
				      " not compressible", s);
		free(s);
		return 0;
	}

	free(s);
	return 1;
}

/*
 * Set compression-related headers on the response.  This might be called even
 * if no compression is done, because we still need to set Vary.
 */
static int
set_compress_headers(TSCont contn, TSEvent event, void *edata)
{
TSHttpTxn	txn = edata;
comp_state_t	*state = TSContDataGet(contn);
TSMBuffer	resp;
TSMLoc		reshdr, hdr;

	TSHttpTxnClientRespGet(txn, &resp, &reshdr);

	/*
	 * This response is compressible.  Add a header and insert our
	 * transform.
	 */
	if (state->cs_type != COMP_NONE) {
		TSMimeHdrFieldCreateNamed(resp, reshdr,
					  TS_MIME_FIELD_CONTENT_ENCODING,
					  TS_MIME_LEN_CONTENT_ENCODING,
					  &hdr);

		switch (state->cs_type) {
		case COMP_GZIP:
			TSMimeHdrFieldValueStringInsert(resp, reshdr, hdr, 0, "gzip", 4);
			break;

		case COMP_BROTLI:
			TSMimeHdrFieldValueStringInsert(resp, reshdr, hdr, 0, "br", 2);
			break;

		default:
			assert(!"unknown cs_type");
		}

		TSMimeHdrFieldAppend(resp, reshdr, hdr);
		TSHandleMLocRelease(resp, reshdr, hdr);
	}

	/*
	 * Set a Vary header to avoid confusing any downstream caches.
	 */
	hdr = TSMimeHdrFieldFind(resp, reshdr,
				 TS_MIME_FIELD_VARY,
				 TS_MIME_LEN_VARY);
	if (hdr) {
		TSMimeHdrFieldValueStringInsert(resp, reshdr, hdr, -1,
				TS_MIME_FIELD_ACCEPT_ENCODING,
				TS_MIME_LEN_ACCEPT_ENCODING);
	} else {
		TSMimeHdrFieldCreateNamed(resp, reshdr,
				TS_MIME_FIELD_VARY, TS_MIME_LEN_VARY, &hdr);
		TSMimeHdrFieldValueStringInsert(resp, reshdr, hdr, -1,
				TS_MIME_FIELD_ACCEPT_ENCODING,
				TS_MIME_LEN_ACCEPT_ENCODING);
		TSMimeHdrFieldAppend(resp, reshdr, hdr);
	}
	TSHandleMLocRelease(resp, reshdr, hdr);

	TSHandleMLocRelease(resp, TS_NULL_MLOC, reshdr);

	TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
	return TS_SUCCESS;
}

static void
compress_init(TSHttpTxn txn, TSCont contn, comp_state_t *state)
{
	/*
	 * Install the compression hooks for whatever type we're using.
	 */
	switch (state->cs_type) {
	case COMP_NONE:
		break;

	case COMP_GZIP:
		state->cs_init = gzip_init;
		state->cs_produce = gzip_produce;
		state->cs_finish = gzip_finish;
		state->cs_free = gzip_free;
		break;

	case COMP_BROTLI:
		state->cs_init = br_init;
		state->cs_produce = br_produce;
		state->cs_finish = br_finish;
		state->cs_free = br_free;
		break;

	default:
		assert(!"unknown cs_type");
	}

	state->cs_input_vio = TSVConnWriteVIOGet(contn);
	state->cs_input_reader = TSVIOReaderGet(state->cs_input_vio);
	state->cs_output_conn = TSTransformOutputVConnGet(contn);
	state->cs_output_buffer = TSIOBufferCreate();
	state->cs_output_reader = TSIOBufferReaderAlloc(
					state->cs_output_buffer);
	state->cs_output_vio = TSVConnWrite(state->cs_output_conn,
			contn, state->cs_output_reader, INT64_MAX);

	if (state->cs_init)
		state->cs_init(state);
	state->cs_done_init = 1;
}

static void
compress_do(TSHttpTxn txn, TSCont contn, comp_state_t *state)
{
TSIOBufferBlock	blk;
int64_t		 avail, toread;

	if (!state->cs_done_init) {
		compress_init(txn, contn, state);
	}

	TSDebug("kubernetes", "compress_do: called");

	if (!TSVIOBufferGet(state->cs_input_vio)) {
	int64_t	written = 0;
		TSDebug("kubernetes", "no input buffer");

		written = state->cs_finish(state);
		state->cs_output_len += written;

		TSVIONBytesSet(state->cs_output_vio, state->cs_output_len);
		TSVIOReenable(state->cs_output_vio);
		return;
	}

	toread = TSVIONTodoGet(state->cs_input_vio);
	TSDebug("kubernetes", "toread=%ld", (long) toread);

	while((avail = TSIOBufferReaderAvail(state->cs_input_reader)) > 0) {
	int64_t		 written = 0;
	const char	*inbuf;
	int64_t		 inbuflen;

		TSDebug("kubernetes", "compress_do: entering; avail=%ld", (long) avail);

		/* Fetch the next available data */
		blk = TSIOBufferReaderStart(state->cs_input_reader);
		inbuf = TSIOBufferBlockReadStart(blk, state->cs_input_reader,
						 &inbuflen);
		TSDebug("kubernetes", "compress_do: read %d bytes", (int) inbuflen);

		written = state->cs_produce(state, (const unsigned char *) inbuf,
					    inbuflen);
		TSDebug("kubernetes", "compress_do: flushing %ld",
			(long) written);

		/* Indicate that we have consumed the data */
		TSIOBufferReaderConsume(state->cs_input_reader, inbuflen);
		TSVIONDoneSet(state->cs_input_vio,
				TSVIONDoneGet(state->cs_input_vio) + inbuflen);
		toread -= inbuflen;
		state->cs_output_len += written;
	}

	if (toread) 
		TSContCall(TSVIOContGet(state->cs_input_vio), TS_EVENT_VCONN_WRITE_READY,
			   state->cs_input_vio);
	else {
		TSContCall(TSVIOContGet(state->cs_input_vio), TS_EVENT_VCONN_WRITE_COMPLETE,
			   state->cs_input_vio);
	}
	TSVIOReenable(state->cs_output_vio);
}

/*
 * Apply compress encoding to a response.
 */
static int
transform_event(TSCont contn, TSEvent event, void *edata)
{
comp_state_t	*state;
TSHttpTxn	 txn;

	TSDebug("kubernetes", "transform_event: event=%d", (int)event);

	/* Connection closed? */
	if (TSVConnClosedGet(contn))
		return TS_SUCCESS;

	/* state may not be valid if the connection has been closed */
	state = TSContDataGet(contn);

	switch (event) {
	case TS_EVENT_ERROR:
		/* Pass error back up the stack */
		TSContCall(TSVIOContGet(state->cs_input_vio), TS_EVENT_ERROR,
			   state->cs_input_vio);
		break;

	case TS_EVENT_VCONN_WRITE_COMPLETE:
		/*
		 * The vconn we're writing to doesn't want any more data.
		 */
		TSVConnShutdown(TSTransformOutputVConnGet(contn), 0, 1);
		break;

		/*
		 * The output vconn is ready for more data.
		 */
	case TS_EVENT_VCONN_WRITE_READY:
	case TS_EVENT_IMMEDIATE:
		txn = state->cs_txn;
		compress_do(txn, contn, state);
		break;

	default:
		assert(!"transform_event: unknown event");
	}

	return TS_SUCCESS;
}

/*
 * Remove an Accept-Encoding header from the request sent to the server.  We do
 * this so the server doesn't compress the response.
 */
static int
remove_aenc(TSCont contn, TSEvent event, void *edata)
{
TSHttpTxn	txn = edata;
TSMBuffer	reqp;
TSMLoc		reqhdr, aenc;

	assert(event == TS_EVENT_HTTP_SEND_REQUEST_HDR);

	TSHttpTxnServerReqGet(txn, &reqp, &reqhdr);
	aenc = TSMimeHdrFieldFind(reqp, reqhdr, "Accept-Encoding", -1);
	if (aenc) {
		TSDebug("kubernetes",
			"compress_hook: removing Accept-Encoding");
		TSMimeHdrFieldDestroy(reqp, reqhdr, aenc);
		TSHandleMLocRelease(reqp, reqhdr, aenc);
	}
	TSHandleMLocRelease(reqp, TS_NULL_MLOC, reqhdr);

	TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
	return TS_SUCCESS;
}

static int
check_server_response(TSCont contn, TSEvent event, void *edata)
{
TSHttpTxn	 txn = edata;
TSMBuffer	 resp;
TSMLoc		 hdr;
comp_state_t	*state = TSContDataGet(contn);

	/* Check if the response is compressible */
	if (TSHttpTxnServerRespGet(txn, &resp, &hdr) != TS_SUCCESS) {
		TSDebug("kubernetes", "check_server_response: cannot get resp?!");
		return TS_ERROR;
	}

	if (response_can_compress(state, resp, hdr)) {
	TSCont	transform;

		/* Tell TS not to cache the transformed data */
		TSHttpTxnTransformedRespCache(txn, 0);
		TSHttpTxnUntransformedRespCache(txn, 1);

		transform = TSTransformCreate(transform_event, txn);
		TSContDataSet(transform, state);
		TSHttpTxnHookAdd(txn, TS_HTTP_RESPONSE_TRANSFORM_HOOK,
				 transform);
	}

	TSHandleMLocRelease(resp, TS_NULL_MLOC, hdr);
	TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
	return TS_SUCCESS;
}

int
check_cached_response(TSCont contn, TSEvent event, void *edata)
{
TSHttpTxn	 txn = edata;
TSMBuffer	 resp;
TSMLoc		 hdr;
comp_state_t	*state = TSContDataGet(contn);
int		 cache_status;

	/*
	 * If we didn't get a cache hit, do nothing and wait for the server
	 * response hook to run.
	 */
	TSHttpTxnCacheLookupStatusGet(txn, &cache_status);
	if (cache_status != TS_CACHE_LOOKUP_HIT_FRESH) {
		TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
		return TS_SUCCESS;
	}

	/* Check if the response is compressible */
	if (TSHttpTxnCachedRespGet(txn, &resp, &hdr) != TS_SUCCESS) {
		TSDebug("kubernetes", "check_cached_response: cannot get resp?!");
		return TS_ERROR;
	}

	if (response_can_compress(state, resp, hdr)) {
	TSCont	transform;

		/* Tell TS not to cache the transformed data */
		TSHttpTxnTransformedRespCache(txn, 0);
		TSHttpTxnUntransformedRespCache(txn, 1);

		transform = TSTransformCreate(transform_event, txn);
		TSContDataSet(transform, state);
		TSHttpTxnHookAdd(txn, TS_HTTP_RESPONSE_TRANSFORM_HOOK,
				 transform);
	}

	TSHandleMLocRelease(resp, TS_NULL_MLOC, hdr);
	TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
	return TS_SUCCESS;
}

/*
 * Called on READ_REQUEST_HDR_HOOK.  Check whether the client can support
 * compression; if so, install our transform hook.  We may still end up not
 * compressing the response, e.g. if it's not in the list of supported types.
 */
static int
check_compress(TSCont contn, TSEvent event, void *edata)
{
TSHttpTxn	txn = edata;
TSMBuffer	reqp;
TSMLoc		hdr;
comp_state_t	*state = TSContDataGet(contn);

	assert(event == TS_EVENT_HTTP_READ_REQUEST_HDR);

	TSHttpTxnClientReqGet(txn, &reqp, &hdr);
	state->cs_type = request_can_compress(reqp, hdr);
	TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdr);

	if (state->cs_type != COMP_NONE) {
	TSCont	c;

		TSDebug("kubernetes", "check_compress: request is compressible");

		c = TSContCreate(remove_aenc, TSMutexCreate());
		TSContDataSet(c, state);
		TSHttpTxnHookAdd(txn, TS_HTTP_SEND_REQUEST_HDR_HOOK, c);

		c = TSContCreate(check_server_response, TSMutexCreate());
		TSContDataSet(c, state);
		TSHttpTxnHookAdd(txn, TS_HTTP_READ_RESPONSE_HDR_HOOK, c);

		c = TSContCreate(check_cached_response, TSMutexCreate());
		TSContDataSet(c, state);
		TSHttpTxnHookAdd(txn, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, c);
	}

	TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
	return TS_SUCCESS;
}

/*
 * Clean up the request and free our state.
 */
static int
free_state(TSCont contn, TSEvent event, void *edata)
{
comp_state_t	*state = TSContDataGet(contn);
TSHttpTxn	 txn = edata;

	TSDebug("kubernetes", "free_state: running");
	assert(event == TS_EVENT_HTTP_TXN_CLOSE);
	comp_state_free(state);
	TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
	return TS_SUCCESS;
}

/*
 * Set up compression for a request for the given remap_path.
 *
 * We can't assume the remap_path will still be around by the time the response
 * comes back, so we have to copy the hash containing the compressible types.
 * This is not ideal; it would be better if hash was refcounted.
 */
void
tsi_compress(remap_path_t *rp, TSHttpTxn txn)
{
const char	*k;
size_t		 klen;
comp_state_t	*state;
TSCont		 contn;

	state = calloc(1, sizeof(*state));
	state->cs_types = hash_new(127, NULL);
	state->cs_txn = txn;

	hash_foreach(rp->rp_compress_types, &k, &klen, NULL)
		hash_setn(state->cs_types, k, klen, HASH_PRESENT);

	/* Set headers (Content-Encoding, Vary, ...) */
	contn = TSContCreate(set_compress_headers, TSMutexCreate());
	TSContDataSet(contn, state);
	TSHttpTxnHookAdd(txn, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contn);

	contn = TSContCreate(check_compress, TSMutexCreate());
	TSContDataSet(contn, state);
	TSHttpTxnHookAdd(txn, TS_HTTP_READ_REQUEST_HDR_HOOK, contn);

	contn = TSContCreate(free_state, TSMutexCreate());
	TSContDataSet(contn, state);
	TSHttpTxnHookAdd(txn, TS_HTTP_TXN_CLOSE_HOOK, contn);
}
