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

package main

import (
	"os"
	"fmt"
	"strings"
	"strconv"
	"unsafe"
	"net/url"
)

/*
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
#include <stdlib.h>
#include <ts/ts.h>
#include <ts/apidefs.h>
#include <ts/remap.h>

static inline void
ts_error_wrapper(const char *s) {
	TSError("[kubernetes_remap] %s", s);
}

static inline void
ts_debug_wrapper(const char *s) {
	TSDebug("kubernetes_remap", "%s", s);
}
*/
import "C"

func ts_error(s string, args ...interface{}) {
	str := fmt.Sprintf(s, args...)
	cstr := C.CString(str)
	defer C.free(unsafe.Pointer(cstr))

	C.ts_error_wrapper(cstr)
}

func ts_debug(s string, args ...interface{}) {
	str := fmt.Sprintf(s, args...)
	cstr := C.CString(str)
	defer C.free(unsafe.Pointer(cstr))

	C.ts_debug_wrapper(cstr)
}

//export TSRemapInit
func TSRemapInit(api *C.TSRemapInterface, errbuf *C.char, bufsz C.int) C.TSReturnCode {
	return C.TS_SUCCESS
}

//export TSRemapNewInstance
func TSRemapNewInstance(argc C.int, argv **C.char, instance *unsafe.Pointer,
			errbuf *C.char, errbuf_size C.int) C.TSReturnCode {
	var kubeconfig string

	/* Convert argv from a C array of pointers to a Go slice, removing the
	 * first two arguments, which are remap source and dest. */
	args := (*[1<<30]*C.char)(unsafe.Pointer(argv))[2:int(argc)]

	for _, arg := range args {
		sarg := C.GoString(arg)
		bits := strings.SplitN(sarg, "=", 2)

		switch bits[0] {
		case "--kubeconfig":
			if len(bits) < 2 {
				ts_error("--kubeconfig requires an argument")
				return C.TS_ERROR
			}

			kubeconfig = bits[1]

		default:
			ts_error("unknown argument %s", bits[0])
			return C.TS_ERROR
		}
	}

	controller, err := makeController(kubeconfig)
	if err != nil {
		ts_error("failed to create controller: %s", err)
		return C.TS_ERROR
	}

	go controller.Run()
	*instance = unsafe.Pointer(controller)

	return C.TS_SUCCESS
}

//export TSRemapDeleteInstance
func TSRemapDeleteInstance(instance unsafe.Pointer) {
	/*
	 * Go shared objects cannot be unloaded when goroutines are running.
	 * So when trafficserver tries to reload or shutdown, we just exit.
	 * traffic_manager will restart us if necessary.
	 */
	ts_error("This plugin cannot be unloaded -- will exit now")
	os.Exit(0)
}

//export TSRemapDoRemap
func TSRemapDoRemap(instance unsafe.Pointer, txn C.TSHttpTxn, rri *C.TSRemapRequestInfo) C.TSRemapStatus {
	cllr := (*Controller)(instance)

	var curl *C.char
	var curllen C.int

	curl = C.TSHttpTxnEffectiveUrlStringGet(txn, &curllen);
	surl := C.GoStringN(curl, curllen)

	ts_debug("remapping URL <%s>", surl)
	url, err := url.Parse(surl)
	if err != nil {
		ts_debug("cannot parse URL: <%s>", surl)
		return C.TSREMAP_NO_REMAP
	}

	host, err := cllr.remap(url)
	if err != nil {
		ts_debug("remap for <%s> failed: %s", surl, err)
		return C.TSREMAP_NO_REMAP
	}

	ts_debug("remapped <%s> to <%s>", surl, host)
	hostbits := strings.Split(host, ":")
	cremap := C.CString(hostbits[0])
	C.TSUrlHostSet(rri.requestBufp, rri.requestUrl, cremap, C.int(len(hostbits[0])))
	C.free(unsafe.Pointer(cremap))

	port, err := strconv.Atoi(hostbits[1])
	if err != nil {
		ts_error("invalid port in destination? <%s>", hostbits[1])
		return C.TSREMAP_NO_REMAP
	}

	C.TSUrlPortSet(rri.requestBufp, rri.requestUrl, C.int(port))

	cscheme := C.CString("http")
	C.TSUrlSchemeSet(rri.requestBufp, rri.requestUrl, cscheme, C.int(4))
	C.free(unsafe.Pointer(cscheme))

	return C.TSREMAP_DID_REMAP
}

func main() {
}
