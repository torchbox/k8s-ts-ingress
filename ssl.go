/* vim:set sw=8 ts=8 noet: */

package main

import (
	"log"
	"strings"
	"time"
	"sync"
	"errors"
	"unsafe"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/pkg/util/wait"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/fields"
)

/*
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
#include <stdlib.h>
#include <ts/ts.h>
#include <ts/apidefs.h>
#include <ts/remap.h>
#include <openssl/ssl.h>

extern int k8s_sni_callback(TSCont, TSEvent, void*);
extern void TSPluginInit_impl(int, char **);
extern int k8s_sni_callback_wrapper(TSCont contn, TSEvent evt, void *edata);

*/
import "C"

type Namespace struct {
	ingresses	map[string] *v1beta1.Ingress
	secrets		map[string] *v1.Secret
}

type Controller struct {
	Clientset	*kubernetes.Clientset
	Config		*rest.Config

	active_map	map[string] *C.SSL_CTX
	map_lock	sync.RWMutex

	freelist	[] *C.SSL_CTX
	namespaces	map[string]*Namespace

	obj_add		chan interface{}
	obj_del		chan interface{}

	changed		bool
}

var cllr *Controller

func ssl_ctx_from_secret(secret *v1.Secret) (*C.SSL_CTX, error) {
	cert, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, errors.New("secret is missing TLS certificate")
	}

	key, ok := secret.Data["tls.key"]
	if !ok {
		return nil, errors.New("secret is missing TLS key")
	}

	ctx := C.SSL_CTX_new(C.SSLv23_server_method())

	cert_bio := C.BIO_new(C.BIO_s_mem())
	defer C.BIO_free(cert_bio)
	C.BIO_write(cert_bio, unsafe.Pointer(&cert[0]), C.int(len(cert)))

	certificate := C.PEM_read_bio_X509_AUX(cert_bio, nil, nil, nil)
	if certificate == nil {
		return nil, errors.New("PEM_read_bio_X509 failed")
	}

	if C.SSL_CTX_use_certificate(ctx, certificate) < 1 {
		return nil, errors.New("SSL_CTX_use_certificate failed")
	}

	for {
		chain := C.PEM_read_bio_X509(cert_bio, nil, nil, nil)
		if chain == nil {
			break
		}

		if C.SSL_CTX_ctrl(ctx, C.SSL_CTRL_EXTRA_CHAIN_CERT, 0, unsafe.Pointer(chain)) < 1 {
			return nil, errors.New("SSL_CTX_add0_chain_cert failed")
		}
	}

	key_bio := C.BIO_new(C.BIO_s_mem())
	defer C.BIO_free(key_bio)
	C.BIO_write(key_bio, unsafe.Pointer(&key[0]), C.int(len(key)))

	private_key := C.PEM_read_bio_PrivateKey(key_bio, nil, nil, nil)
	if private_key == nil {
		return nil, errors.New("PEM_read_bio_PrivateKey failed")
	}

	if C.SSL_CTX_use_PrivateKey(ctx, private_key) < 1 {
		return nil, errors.New("SSL_CTX_use_PrivateKey failed")
	}

	return ctx, nil
}

func (cllr *Controller) rebuild() {
	newmap := make(map[string] *C.SSL_CTX)
	freelist := cllr.freelist
	cllr.freelist = nil

	for _, namespace := range cllr.namespaces {
		for _, ingress := range namespace.ingresses {
			for _, tls := range ingress.Spec.TLS {
				secret, ok := namespace.secrets[tls.SecretName]
				if !ok {
					continue
				}

				ctx, err := ssl_ctx_from_secret(secret)
				if err != nil {
					log.Printf("ingress %s/%s: ssl ctx failed: %s",
						   ingress.Namespace, ingress.Name, err)
					continue
				}

				cllr.freelist = append(cllr.freelist, ctx)
				for _, host := range tls.Hosts {
					newmap[host] = ctx
				}
			}
		}
	}

	cllr.map_lock.Lock()
	cllr.active_map = newmap
	cllr.map_lock.Unlock()

	for _, ctx := range freelist {
		C.SSL_CTX_free(ctx)
	}
}

func (cllr *Controller) getNamespace(name string) *Namespace {
	ns, ok := cllr.namespaces[name]
	if ok {
		return ns
	}

	ns = &Namespace{
		ingresses:	make(map[string]*v1beta1.Ingress),
		secrets:	make(map[string]*v1.Secret),
	}
	cllr.namespaces[name] = ns
	return ns
}

func makeController (kubeconfig string) (*Controller, error) {
	cllr := &Controller{}

	var err error

	if kubeconfig != "" {
		cllr.Config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cllr.Config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}

	cllr.Clientset, err = kubernetes.NewForConfig(cllr.Config)
	if err != nil {
		return nil, err
	}

	cllr.obj_add = make(chan interface{})
	cllr.obj_del = make(chan interface{})
	cllr.namespaces = make(map[string]*Namespace)
	return cllr, nil
}

func (cllr *Controller) Run() {
	eventhandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cllr.obj_add <- obj
		},
		DeleteFunc: func(obj interface{}) {
			cllr.obj_del <- obj
		},
		UpdateFunc: func(oldobj, obj interface{}) {
			cllr.obj_add <- obj
		},
	}

	ilist := cache.NewListWatchFromClient(cllr.Clientset.ExtensionsV1beta1().RESTClient(),
			"ingresses", v1.NamespaceAll, fields.Everything())
	_, ic := cache.NewInformer(ilist, &v1beta1.Ingress{}, time.Second * 30, eventhandler)
	go ic.Run(wait.NeverStop)

	slist := cache.NewListWatchFromClient(cllr.Clientset.Core().RESTClient(),
			"secrets", v1.NamespaceAll, fields.Everything())
	_, sc := cache.NewInformer(slist, &v1.Secret{}, time.Second * 30, eventhandler)
	go sc.Run(wait.NeverStop)

	for {
		select {
		case obj := <-cllr.obj_add:
			cllr.changed = true

			switch res := obj.(type) {
			case *v1beta1.Ingress:
				ns := cllr.getNamespace(res.Namespace)
				ns.ingresses[res.Name] = res

			case *v1.Secret:
				ns := cllr.getNamespace(res.Namespace)
				ns.secrets[res.Name] = res
			}

		case obj := <-cllr.obj_del:
			cllr.changed = true

			switch res := obj.(type) {
			case *v1beta1.Ingress:
				ns := cllr.getNamespace(res.Namespace)
				delete(ns.ingresses, res.Name)

			case *v1.Secret:
				ns := cllr.getNamespace(res.Namespace)
				delete(ns.secrets, res.Name)
			}

		case <-time.After(time.Second * 1):
			if cllr.changed {
				log.Printf("[kubernetes] rebuilding SSL host map\n")
				cllr.rebuild()
				cllr.changed = false
			}
		}
	}
}

//export k8s_sni_callback
func k8s_sni_callback (contn C.TSCont, evt C.TSEvent, edata unsafe.Pointer) C.int {
	ssl_vc := (C.TSVConn)(edata)
	ssl := unsafe.Pointer(C.TSVConnSSLConnectionGet(ssl_vc))
	c_servername := C.SSL_get_servername((*C.SSL) (ssl), C.TLSEXT_NAMETYPE_host_name)
	servername := C.GoString(c_servername)

	log.Printf("doing SNI map for [%s]\n", servername)

	cllr.map_lock.RLock()
	defer cllr.map_lock.RUnlock()

	ctx, ok := cllr.active_map[servername]
	if !ok {
		log.Printf("[kubernetes_ssl] for host %s, no ctx\n", servername)
		return C.int(0)
	}

	log.Printf("set own ctx\n")
	C.SSL_set_SSL_CTX((*C.SSL)(ssl), ctx)
	C.TSVConnReenable(ssl_vc)
	return C.TS_SUCCESS
}

//export TSPluginInit_impl
func TSPluginInit_impl(argc C.int, argv **C.char) {
	var kubeconfig string
	var info C.TSPluginRegistrationInfo

	info.plugin_name = C.CString("Kubernetes SSL loader")
	info.vendor_name = C.CString("Torchbox, Ltd.")
	info.support_email = C.CString("sysadmin@torchbox.com")

	if C.TSPluginRegister(&info) != C.TS_SUCCESS {
		log.Printf("[kubernetes_ssl] Plugin registration failed.\n")
		return
	}

	cb_sni := C.TSContCreate((*[0]byte)(C.k8s_sni_callback_wrapper), C.TSMutexCreate())
	if cb_sni == nil {
		log.Printf("[kubernetes_ssl] Failed to create continuation\n")
		return
	}

	C.TSHttpHookAdd(C.TS_SSL_SNI_HOOK, cb_sni)

	args := (*[1<<30]*C.char)(unsafe.Pointer(argv))[1:int(argc)]

	for _, arg := range args {
		sarg := C.GoString(arg)
		bits := strings.SplitN(sarg, "=", 2)

		switch bits[0] {
		case "--kubeconfig":
			if len(bits) < 2 {
				log.Printf("[kubernetes] --kubeconfig requires an argument\n")
				return
			}

			kubeconfig = bits[1]

		default:
			log.Printf("[kubernetes] unknown argument %s\n", bits[0])
			return
		}
	}

	var err error
	cllr, err = makeController(kubeconfig)
	if err != nil {
		log.Printf("[kubernetes] failed to create controller: %s", err)
		return
	}

	go cllr.Run()
}

func main() {
}
