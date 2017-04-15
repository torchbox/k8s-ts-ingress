/* vim:set sw=8 ts=8 noet: */

package main

import (
	"log"
	"fmt"
	"strings"
	"errors"
	"time"
	"sync"
	"reflect"
	"net/url"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/pkg/util/wait"
	"k8s.io/client-go/pkg/util/intstr"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/fields"
)

type PathRoute struct {
	prefix		string
	destinations	[]string
}

type HostRoute struct {
	paths		[]*PathRoute
}

type RouteMap struct {
	hosts		map[string]*HostRoute
}

type Namespace struct {
	ingresses	map[string] *v1beta1.Ingress
	services	map[string] *v1.Service
	endpoints	map[string] *v1.Endpoints
	pods		map[string] *v1.Pod
}

type Controller struct {
	Clientset	*kubernetes.Clientset
	Config		*rest.Config

	active_map	*RouteMap
	map_lock	sync.RWMutex

	namespaces	map[string]*Namespace

	obj_add		chan interface{}
	obj_del		chan interface{}

	changed		bool
}

func (cllr *Controller) getDestinations(
		namespace *Namespace,
		serviceName string,
		servicePort intstr.IntOrString) []string {

	var destinations []string

	endpoints, ok := namespace.endpoints[serviceName]
	if !ok {
		log.Printf("didn't find endpoint called [%s]\n", serviceName)
		return destinations
	}

	service, ok := namespace.services[serviceName]
	if !ok {
		log.Printf("didn't find service called [%s]\n", serviceName)
		return destinations
	}

	var portName string
	for _, port := range service.Spec.Ports {
		if port.Protocol != "TCP" {
			continue
		}

		if (servicePort.Type == intstr.String && port.Name == servicePort.StrVal) ||
		   (servicePort.Type == intstr.Int && port.Port == servicePort.IntVal) {
			portName = port.Name
			break
		}
	}

	for _, subset := range endpoints.Subsets {
		var targetPort int32
		for _, port := range subset.Ports {
			if portName == port.Name {
				targetPort = port.Port
				break
			}
		}

		log.Printf("for [%s], targetPort is [%d]\n", serviceName, targetPort)
		if targetPort == 0 {
			continue
		}

		for _, addr := range subset.Addresses {
			log.Printf("found a destination address [%s]\n", addr.IP)
			destinations = append(destinations,
				fmt.Sprintf("%s:%d", addr.IP, targetPort))
		}
	}

	return destinations
}

func (cllr *Controller) rebuild() {
	rm := &RouteMap{
		hosts: make(map[string]*HostRoute),
	}

	for nsname, namespace := range cllr.namespaces {
		for _, ingress := range namespace.ingresses {
			for _, rule := range ingress.Spec.Rules {
				log.Printf("processing rule for host <%+v> for ingress <%s/%s>", rule, nsname, ingress.Name)

				hostroute := rm.hosts[rule.Host]
				if hostroute == nil {
					hostroute = &HostRoute{}
					rm.hosts[rule.Host] = hostroute
				}

				for _, path := range rule.HTTP.Paths {
					pathroute := &PathRoute{
						prefix: path.Path,
						destinations: cllr.getDestinations(
							namespace,
							path.Backend.ServiceName,
							path.Backend.ServicePort),
					}

					hostroute.paths = append(hostroute.paths, pathroute)
				}
			}
		}
	}

	cllr.map_lock.Lock()
	defer cllr.map_lock.Unlock()
	cllr.active_map = rm
}

func (cllr *Controller) getNamespace(name string) *Namespace {
	ns, ok := cllr.namespaces[name]
	if ok {
		return ns
	}

	ns = &Namespace{
		ingresses:	make(map[string]*v1beta1.Ingress),
		endpoints:	make(map[string]*v1.Endpoints),
		services:	make(map[string]*v1.Service),
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

	elist := cache.NewListWatchFromClient(cllr.Clientset.Core().RESTClient(),
			"endpoints", v1.NamespaceAll, fields.Everything())
	_, ec := cache.NewInformer(elist, &v1.Endpoints{}, time.Second * 30, eventhandler)
	go ec.Run(wait.NeverStop)

	slist := cache.NewListWatchFromClient(cllr.Clientset.Core().RESTClient(),
			"services", v1.NamespaceAll, fields.Everything())
	_, sc := cache.NewInformer(slist, &v1.Service{}, time.Second * 30, eventhandler)
	go sc.Run(wait.NeverStop)

	for {
		select {
		case obj := <-cllr.obj_add:
			switch res := obj.(type) {
			case *v1beta1.Ingress:
				ns := cllr.getNamespace(res.Namespace)
				ns.ingresses[res.Name] = res
				cllr.changed = true

			case *v1.Service:
				ns := cllr.getNamespace(res.Namespace)
				ns.services[res.Name] = res
				cllr.changed = true

			case *v1.Endpoints:
				ns := cllr.getNamespace(res.Namespace)
				eps, ok := ns.endpoints[res.Name]
				if !ok || !reflect.DeepEqual(eps.Subsets,
							     res.Subsets) {
					ns.endpoints[res.Name] = res
					cllr.changed = true
				}
			}

		case obj := <-cllr.obj_del:
			cllr.changed = true

			switch res := obj.(type) {
			case *v1.Service:
				ns := cllr.getNamespace(res.Namespace)
				delete(ns.services, res.Name)

			case *v1beta1.Ingress:
				ns := cllr.getNamespace(res.Namespace)
				delete(ns.ingresses, res.Name)

			case *v1.Endpoints:
				ns := cllr.getNamespace(res.Namespace)
				delete(ns.endpoints, res.Name)
			}

		case <-time.After(time.Second * 1):
			if cllr.changed {
				log.Printf("[kubernetes] rebuilding route map\n")
				cllr.rebuild()
				cllr.changed = false
			}
		}
	}
}

/*
 * Given a request URL, return the (host, port) of the backend service.  The
 * path is not changed.
 */
func (cllr *Controller) remap(url *url.URL) (string, error) {
	cllr.map_lock.RLock()
	routemap := cllr.active_map
	cllr.map_lock.RUnlock()

	hostname := strings.Split(url.Host, ":")[0]

	hostmap, ok := routemap.hosts[hostname]
	if !ok {
		return "", errors.New("remap target not found")
	}

	for _, path := range hostmap.paths {
		if strings.HasPrefix(url.Path, path.prefix) {
			if len(path.destinations) == 0 {
				return "", errors.New("path has no destinations")
			}

			return path.destinations[0], nil
		}
	}
	return "", errors.New("remap target not found")
}
