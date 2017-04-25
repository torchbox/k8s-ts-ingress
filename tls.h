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

#ifndef TLS_H
#define TLS_H

#include    <stdlib.h>

#include    <ts/ts.h>
#include    <ts/apidefs.h>
#include    <ts/remap.h>

#include    <openssl/ssl.h>

void TSPluginInit_impl(int, char **);
int k8s_sni_callback(TSCont, TSEvent, void*);
int k8s_sni_callback_wrapper(TSCont contn, TSEvent evt, void *edata);

void ts_error_wrapper(const char *s);
void ts_debug_wrapper(const char *s);

SSL_CTX *make_ssl_ctx(/*const*/ char *certdata, /*const*/ char *keydata);

#endif  /* !TLS_H */
