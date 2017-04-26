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

#include	<stdarg.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	"synth.h"

#define	SY_BUFSZ	16384

static int synth_handle(TSCont, TSEvent, void *);

struct synth {
	char	sy_buf[SY_BUFSZ];
	size_t	sy_bufpos;

	TSVConn			sy_vc;
	TSIOBuffer		sy_req_buffer;
	TSIOBuffer		sy_resp_buffer;
	TSIOBufferReader	sy_resp_reader;
	TSVIO			sy_read_vio;
	TSVIO			sy_write_vio;
};

static int
sy_printf(synth_t *sy, const char *fmt, ...)
{
va_list	args;
int	n;
	va_start(args, fmt);
	n = vsnprintf(sy->sy_buf + sy->sy_bufpos,
		      SY_BUFSZ - sy->sy_bufpos,
		      fmt, args);
	sy->sy_bufpos += n;
	va_end(args);
	return n;
}

synth_t *
synth_new(int status, const char *reason)
{
synth_t	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	sy_printf(ret, "HTTP/1.1 %d %s\r\n", status, reason);
	return ret;
}

void
synth_free(synth_t *sy)
{
	if (sy->sy_req_buffer)
		TSIOBufferDestroy(sy->sy_req_buffer);
	if (sy->sy_resp_buffer)
		TSIOBufferDestroy(sy->sy_resp_buffer);
	TSVConnClose(sy->sy_vc);
	free(sy);
}

void
synth_add_header(synth_t *sy, const char *hdr, const char *val)
{
	sy_printf(sy, "%s: %s\r\n", hdr, val);
}

void
synth_set_body(synth_t *sy, const char *body)
{
	sy_printf(sy, "Content-Length: %d\r\n", strlen(body));
	sy_printf(sy, "\r\n%s", body);
}

void
synth_intercept(synth_t *sy, TSHttpTxn txnp)
{
TSCont	contn;
	contn = TSContCreate(synth_handle, TSMutexCreate());
	TSContDataSet(contn, sy);
	TSHttpTxnIntercept(contn, txnp);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
}

int
synth_handle(TSCont contn, TSEvent event, void *edata)
{
synth_t	*sy = TSContDataGet(contn);

	switch (event) {
	case TS_EVENT_NET_ACCEPT:
		TSDebug("kubernetes", "synth: accepted");
		sy->sy_vc = (TSVConn) edata;
		sy->sy_req_buffer = TSIOBufferCreate();
		sy->sy_resp_buffer = TSIOBufferCreate();
		sy->sy_resp_reader = TSIOBufferReaderAlloc(sy->sy_resp_buffer);
		sy->sy_read_vio = TSVConnRead(sy->sy_vc, contn,
					      sy->sy_req_buffer, INT64_MAX);
		return TS_SUCCESS;

	case TS_EVENT_VCONN_READ_READY:
		TSDebug("kubernetes", "synth: read_ready");
		TSVConnShutdown(sy->sy_vc, 1, 0);
		sy->sy_write_vio = TSVConnWrite(sy->sy_vc, contn,
						sy->sy_resp_reader, INT64_MAX);
		return TS_SUCCESS;

	case TS_EVENT_VCONN_WRITE_READY:
		TSDebug("kubernetes", "synth: write_ready");
		TSIOBufferWrite(sy->sy_resp_buffer, sy->sy_buf, sy->sy_bufpos);
		TSVIONBytesSet(sy->sy_write_vio, sy->sy_bufpos);
		TSVIOReenable(sy->sy_write_vio);
		return TS_SUCCESS;

	case TS_EVENT_VCONN_WRITE_COMPLETE:
		TSDebug("kubernetes", "synth: write_complete");
		synth_free(sy);
		TSContDestroy(contn);
		return TS_SUCCESS;

	default:
		TSDebug("kubernetes", "synth_handle: unexpected event %d",
			(int) event);
		synth_free(sy);
		TSContDestroy(contn);
		return TS_SUCCESS;
	}

	return TS_SUCCESS;
}
