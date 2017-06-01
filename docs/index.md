# Traffic Server ingress controller

**WARNING: This is alpha code, do not use it in production.**  (If you do,
please report bugs.)

[Traffic Server](https://trafficserver.apache.org/) is a high-performance,
extensible HTTP proxy server with a rich feature set, including TLS termination,
caching, and edge-side includes (ESI).  This plugin allows Traffic Server to
act as an [Ingress](https://github.com/kubernetes/ingress) controller for
[Kubernetes](https://kubernetes.io) clusters, providing the reverse proxy that
allows HTTP requests from the Internet to reach Kubernetes pods.

The controller is provided as C source code and as a pre-built Docker image.
If you want to add Kubernetes support to an existing instance of TS, you should
build the plugin from source.  If you want to deploy TS inside a Kubernetes
cluster, you can use the pre-built Docker image.

## Quick start

To deploy the image on an existing Kubernetes 1.6 (or later) cluster:

```sh
$ curl -L https://raw.githubusercontent.com/torchbox/k8s-ts-ingress/master/example-rbac.yaml | kubectl apply -f -
$ curl -L https://raw.githubusercontent.com/torchbox/k8s-ts-ingress/master/example-deployment.yaml | kubectl apply -f -
```

(If you're using 1.5 or earlier, you can still use `example-deployment.yaml`,
but if you need RBAC support you will need to convert `example-rbac.yaml` to use
the old alpha RBAC API.)

This will start two copies of Traffic Server, each with an emptyDir volume for
cache storage, listening on node ports 30080 (http) and 30443 (https).   You can
configure an external load balancer of some sort to route incoming traffic to
those ports, or use Kubernetes'
[keepalived-vip](https://github.com/kubernetes/contrib/tree/master/keepalived-vip)
to manage a virtual IP address on your cluster.

For more detailed installation instructions, see the documentation for
[building from source](source.md) or [Deploying on Kubernetes](docker.md).

## Features

The controller provides the following features:

* Full support for Ingress resources, including many annotations used by other
  controller implementations;
* HTTP/2;
* WebSockets;
* TLS termination, configured in the Ingress resource using Kubernetes Secrets;
* Emulation of the nginx Ingress controller (for services that require it,
  e.g. kube-lego);
* Flexible HTTP caching, including:
    * Cache lifetime controlled by `Cache-Control` or `Expires` headers;
    * Removal from the cache of individual pages or all pages at once;
    * Alternatives (HTTP Vary);
    * Ignoring URL parameters and cookies which do not affect page content.
* HTTP compression (gzip and Brotli);
* Authorization using HTTP Basic authentication or client IP address;
* A complete, configurable CORS implementation;
* Proxying to external (non-Kubernetes) services using Ingress resources;
* ESI (Edge-Side Includes).

More features are planned for future releases.  If you would like to see a
particular feature supported, please
[open a Github issue](https://github.com/torchbox/k8s-ts-ingress/issues).

## Planned features

A feature being listed here indicates we are interested in implementing it, but
provides no guarantee that it will be implemented within any particular time
frame, or ever.

* TLS client certificate authentication.
* Client session affinity
* Proxy protocol
* Rate limiting
* SSL passthrough
* Global / default configuration
* HSTS preload support (in any case, rewrite the HSTS support as it will be
  removed from TS core in some later release)
* HTTP/2 server push
* Custom error bodies
* Improve API watch support by first retrieving all objects, then watching with
  resourceVersion.

## Release history

* 1.0.0-alpha8 (unreleased):
    * No changes yet.

* 1.0.0-alpha7:
    * Improvement: The Traffic Server version in the Docker image has been
        upgraded from 7.0.0 to 7.1.x (prerelease).
    * Improvement: The hash tree implementation has been replaced with a radix
        tree, reducing memory use for small clusters and providing better (and
        more predictable) performance for large clusters.
    * Bug fix: A synthetic response could cause a crash.
    * Bug fix: An incorrect Cookie header could be sent to the origin.
    * Bug fix: An incorrect Content-Encoding header could be sent to the client
        if the client supported compression but the response object was not
        compressed.

* 1.0.0-alpha6:
    * Incompatible change: The behaviour of the `app-root` annotation was
        changed to match the behaviour of other Ingress controllers.
    * Incompatible change: Several annotations were moved from
        `ingress.torchbox.com` to `ingress.kubernetes.io` to improve
         compatibility among Ingress controllers.
    * Feature: The `ingress.kubernetes.io/read-response-timeout` annotation
        was implemented.
    * Feature: CORS annotations were implemented.
    * Feature: HTTP compression was implemented.
    * Feature: For Ingress resources with caching enabled, an `X-Cache-Status`
        header is returned in the response, indicating whether the request was
        cached and the current cache generation.
    * Feature: The `cache-ignore-cookies` annotation was implemented.
    * Bug fix: With certain combinations of OpenSSL and Traffic Server versions,
        a TLS request for an unknown host could hang indefinitely instead of
        returning an error.

* 1.0.0-alpha5:
    * Incompatible change: The `ingress.torchbox.com/auth-address-list`
        annotation was renamed to `ingress.torchbox.com/whitelist-source-range`,
        and is now comma-delimited, for compatibility with other Ingress
        controllers.
    * Feature: Support Ingress classes.
    * Feature: The X-Forwarded-Proto header is now (optionally) sent to the
        backend.
    * Feature: The `cache-whitelist-params` and `cache-ignore-params`
        annotations were implemented.
    * Feature: The `tls_verify` configuration option was added.
    * Improvement: The API server connection code was reimplemented using cURL,
        making it more reliable and featureful.
    * Bug fix: TLS redirects with an empty URL path could crash.
    * Bug fix: TLS secret handling could leak memory.
    * Bug fix: with some combinations of Traffic Server and OpenSSL versions,
        TLS certificates might not be loaded correctly.  Use the new
        TS_SSL_CERT_HOOK hook to ensure this works properly in all cases.
    * Bug fix: An Endpoints with more than one port or address could be parsed
        incorrectly or cause a crash.

* 1.0.0-alpha4:
    * Do not return a client error if the requested host or path was not
      found, to allow use with other plugins like healthchecks.

* 1.0.0-alpha3:
    * Greatly improved unit test coverage.
    * Several minor bugs fixed.
    * Support configuration via environment variables.

* 1.0.0-alpha2: Implement IP address authentication.
* 1.0.0-alpha1: Initial release.

## License and credits

This plugin was developed by Felicity Tarnell (ft@le-Fay.ORG) for
[Torchbox Ltd.](https://torchbox.com).  Copyright (c) 2016-2017 Torchbox Ltd.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely. This software is provided 'as-is', without any express or implied
warranty.

----

`crypt_bf.c` was written by Solar Designer, and is released into the public
domain.

`crypt_des.c` is copyright (c) 1989, 1993 The Regents of the University of
California, based on code written by Tom Truscott.

`crypt_md5.c` was written by Poul-Henning Kamp, and is released under the
"beer-ware" license.

`crypt_sha256.c` and `crypt_sha512.c` were written by Ulrich Drepper, and are
released into the public domain.

`strmatch.c` is copyright (c) 1989, 1993, 1994 The Regents of the University
of California, based on code written by Guido van Rossum.

`contrib/rax` is Copyright (c) 2017, Salvatore Sanfilippo <antirez at gmail dot com>

`contrib/brotli` is Copyright 2013 Google Inc.

`base64.c` is copyright (c) 2011-2017 Felicity Tarnell.
