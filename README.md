Traffic Server ingress controller for Kubernetes
================================================

*Note*: This software is still in development.  While we are using it internally,
we do not recommend deploying it in a production cluster at this time.

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
* HTTP response caching (including `PURGE` support, efficient whole-domain
  purging, outgoing Cache-Control manipulation, and the ability to ignore
  certain cookies or URL param)
* Flexible HTTP caching, including:
    * Cache lifetime controlled by `Cache-Control` or `Expires` headers;
    * Manipulation of outgoing Cache-Control;
    * Support for `PURGE` of individual pages, or efficient clearing of the
      entire cache;
    * Alternatives (HTTP Vary);
    * Improve cache hit rate by ignoring URL parameters and cookies which do not
      affect page content.
* Domain access control (configure which namespaces can use which domains)
* Default TLS certificates (e.g. use one wildcard certificate for all Ingresses
  in that domain)
* On-the-fly HTTP compression
* Proxying to external services (via Endpoints or ExternalName)
* Fully configurable CORS response headers
* nginx Ingress controller compatibility, including kube-lego support
* Access control by HTTP Basic authentication, client IP address, or both

## Planned features

A feature being listed here indicates we are interested in implementing it, but
provides no guarantee that it will be implemented within any particular time
frame, or ever.

If you would like to see a particular feature supported, whether it's on this
list or not, please
[open a Github issue](https://github.com/torchbox/k8s-ts-ingress/issues).

* TLS client certificate authentication.
* Client session affinity
* Backend weights
* Proxy protocol
* Rate limiting
* HSTS preload support (in any case, rewrite the HSTS support as it will be
  removed from TS core in some later release)
* Custom error bodies
* Support [libslz](http://www.libslz.org/) as an alternative to zlib.
* Wildcard cache purging and/or cache tags.
* Clustering (HTCP)
* Modify response headers (`header-{add,replace}-Name`)
* Incoming XFF
* SSL passthrough

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
