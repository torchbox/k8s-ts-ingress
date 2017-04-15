/* vim:set sw=8 ts=8 noet: */

/*
 * Due to limitations in cgo, the implementation of TSPluginInit can't be in
 * a file that uses //export.
 */
package main

/*
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
#include <stdlib.h>
#include <ts/ts.h>
#include <ts/apidefs.h>
#include <ts/remap.h>

extern int k8s_sni_callback(TSCont, TSEvent, void*);
extern void TSPluginInit_impl(int, char **);

int
k8s_sni_callback_wrapper(TSCont contn, TSEvent evt, void *edata) {
	return k8s_sni_callback(contn, evt, edata);
}

void
TSPluginInit(int argc, const char *argv[]) {
	return TSPluginInit_impl(argc, (char **) argv);
}
*/
import "C"
