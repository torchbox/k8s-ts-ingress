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
struct remap_host	*rh;

	TSDebug("kubernetes_tls", "doing SNI map for [%s]", host);

	TSMutexLock(state->map_lock);
	if ((rh = hash_get(state->map, host)) == NULL) {
		TSDebug("kubernetes", "[%s] TLS SNI: host not found", host);
		TSMutexUnlock(state->map_lock);
		return TS_SUCCESS;
	}

	if (!rh->rh_ctx) {
		TSDebug("kubernetes", "[%s] TLS SNI: host found, but not ctx",
			host);
		TSMutexUnlock(state->map_lock);
		return TS_SUCCESS;
	}

	SSL_set_SSL_CTX(ssl, rh->rh_ctx);
	TSVConnReenable(ssl_vc);
	TSMutexUnlock(state->map_lock);

	return TS_SUCCESS;
}

