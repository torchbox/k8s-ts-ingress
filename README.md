Traffic Server ingress controller for Kubernetes
================================================

**WARNING: This is alpha code, do not use it in production.**

This is a Kubernetes ingress controller plugin for
[Traffic Server](https://trafficserver.apache.org/), a high-performance,
extensible HTTP proxy server.  The Ingress controller allows Traffic Server to
act as an ingress controller for Kubernetes clusters, routing incoming requests
to pods while providing TLS termination, caching, ESI and other standard
Traffic Server features.

The controller is provided as C source code and as a pre-built Docker image.
If you want to add Kubernetes support to an existing instance of TS, you should
build the plugin from source.  If you want to deploy TS inside a Kubernetes
cluster, you can use the pre-built Docker image.

## Features

* HTTP/2, including Server Push
* Websockets
* HTTP response caching (including `PURGE` support and outgoing Cache-Control
  manipulation)
* Default TLS certificates (e.g. use one wildcard certificate for all Ingresses
  in that domain)
* On-the-fly HTTP compression
* Proxying to external services (via Endpoints or ExternalName)
* Fully configurable CORS response headers
* kube-lego support
* Access control by HTTP Basic authentication, client IP address, or both

## Quick start

To deploy the image on an existing Kubernetes 1.6 (or later) cluster:

```sh
$ curl -L https://raw.githubusercontent.com/torchbox/k8s-ts-ingress/master/example-rbac.yaml | kubectl apply -f -
$ curl -L https://raw.githubusercontent.com/torchbox/k8s-ts-ingress/master/example-deployment.yaml | kubectl apply -f -
```

This will start two copies of Traffic Server, each with an emptyDir volume for
cache storage, listening on node ports 30080 (http) and 30443 (https).   You can
configure an external load balancer of some sort to route incoming traffic to
those ports, or use Kubernetes'
[keepalived-vip](https://github.com/kubernetes/contrib/tree/master/keepalived-vip)
to manage a virtual IP address on your cluster.

For more detailed installation and configuration instructions, read the
[documentation](https://torchbox.github.io/k8s-ts-ingress/).
