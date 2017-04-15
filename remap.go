/* vim:set sw=8 ts=8 noet: */

package main

import (
	"os"
	"log"
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
*/
import "C"

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
				log.Printf("[kubernetes] --kubeconfig requires an argument\n")
				return C.TS_ERROR
			}

			kubeconfig = bits[1]

		default:
			log.Printf("[kubernetes] unknown argument %s\n", bits[0])
			return C.TS_ERROR
		}
	}

	controller, err := makeController(kubeconfig)
	if err != nil {
		log.Printf("[kubernetes] failed to create controller: %s", err)
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
	log.Printf("[kubernetes] This plugin cannot be unloaded -- will exit now")
	os.Exit(0)
}

//export TSRemapDoRemap
func TSRemapDoRemap(instance unsafe.Pointer, txn C.TSHttpTxn, rri *C.TSRemapRequestInfo) C.TSRemapStatus {
	cllr := (*Controller)(instance)

	var curl *C.char
	var curllen C.int

	curl = C.TSHttpTxnEffectiveUrlStringGet(txn, &curllen);
	surl := C.GoStringN(curl, curllen)

	log.Printf("[kubernetes] remapping URL <%s>\n", surl)
	url, err := url.Parse(surl)
	if err != nil {
		log.Printf("[kubernetes] cannot parse URL: <%s>\n", surl)
		return C.TSREMAP_NO_REMAP
	}

	host, err := cllr.remap(url)
	if err != nil {
		log.Printf("[kubernetes] remap for <%s> failed: %s",
			   surl, err)
		return C.TSREMAP_NO_REMAP
	}

	log.Printf("[kubernetes] remapped <%s> to <%s>\n", surl, host)
	hostbits := strings.Split(host, ":")
	cremap := C.CString(hostbits[0])
	C.TSUrlHostSet(rri.requestBufp, rri.requestUrl, cremap, C.int(len(hostbits[0])))
	C.free(unsafe.Pointer(cremap))

	port, err := strconv.Atoi(hostbits[1])
	if err != nil {
		log.Printf("[kubernetes] invalid port in destination? <%s>\n",
			   hostbits[1])
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
