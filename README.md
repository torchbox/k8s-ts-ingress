Apache Traffic Server ingress controller for Kubernetes
=======================================================

**WARNING: This is alpha code, do not use it in production.**

This is a Kubernetes ingress controller plugin for
[Apache Traffic Server](https://trafficserver.apache.org/).  It allows Traffic
Server to act as an ingress controller for Kubernetes clusters, routing incoming
requests to pods while providing TLS termination, caching, ESI and other standard
Traffic Server features.

The plugin is only supported with Traffic Server 7.0+.  It may work with 6.x
versions, but has not been tested.  It definitely won't work with 5.x or older
versions without modifications, as the plugin API has changed.

Depending on Traffic Server version, the following protocols are supported:

* HTTP/1.0, HTTP/1.1, HTTP/2
* WebSockets (ws and wss)
* TLSv1, TLSv1.1, TLSv1.2

Web socket support is transparent; an incoming websocket request will be routed
directly to the backend.

Advanced HTTP/2 features like server push are not currently supported.

Why Traffic Server?
-------------------

The primary reason to use TS as an Ingress controller is caching.  TS provides
highly configurable, fast and well-tested memory- and disk-based caching of HTTP
requests.  Using caching allows an application or cluster to serve significantly
higher request load than it could if the application had to respond to every
request itself.

This is true even if the application has its own caching layer; with a sufficiently
high cache hit ratio, a 12-CPU single machine running Traffic Server can serve
requests at upwards of 40Gbps.  Traffic Server was developed by Yahoo! for use
in high traffic environments, and is used by other large sites such as Akamai,
LinkedIn, and Comcast.

A secondary reason to use TS is its plugin support; it has a stable and
well-developed plugin API allowing plugins (like this one) to extend its
functionality.

Using the Docker image
----------------------

We provide a pre-built version of Traffic Server, including the plugin.  If you
use this pre-built image, you do not need to build the plugin manually.

Current image: `docker.io/torchbox/k8s-ts-ingress:v1.0.0-alpha4`

Deploying the Docker image on Kubernetes
----------------------------------------

We provide an `example-daemonset.yaml` containing a sample configuration for
deploying the controller as a Kubernetes DaemonSet.  Please read the entire file
and edit it for your needs before using it.

Unfortunately, there are many different ways to expose an Ingress controller on
Kubernetes, and we can't document every possible variation, so you will need to
decide what method is best for your cluster.  The example configuration uses a
`hostPort`, which is suitable for use with an external load balancer in either
self-hosted clusters or using a cloud provider.

You can set the following environment variables to configure Traffic Server:

* `TS_CACHE_SIZE`: Size of the on-disk cache file to create, in megabytes.

Most of the configuration options from `kubernetes.config` can also be set in
the environment; see `kubernetes.config.example` for details.

In addition, any TS configuration (records.config) setting can be
overridden in the environment:

https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.config.en.html#environment-overrides

For persistent cache storage, mount a volume on `/var/lib/trafficserver`.  This
can be a persistent volume or an emptyDir; any necessary files, including the
cache store, will be created at startup.  If using a persistent volume, be aware
that only one instance of TS can access the cache at once.  If you are running
multiple copies, you will need to create a separate PV for each instance
(perhaps by using a StatefulSet instead of a DaemonSet).

Building
--------

Requirements:

* Traffic Server 7.0 or later (including development headers).
* A working C99 compiler and `make` utility.
* json-c library
* cURL library
* OpenSSL (or a compatible TLS library, e.g. LibreSSL)

Build and install the plugin:

```
$ autoreconf -if            # only if building from a git checkout
$ ./configure [--with-tsxs=/path/to/trafficserver/bin/tsxs]
$ make
# make install
```

Optionally, run the test suite (requires a C++11 compiler):

```
$ make test
```

Configuration
-------------

Run `make install` to install the plugin, or copy `kubernetes.so` to the
Traffic Server plugin directory (e.g.  `/usr/local/libexec/trafficserver`).
Edit `plugin.config` to load the plugin.

If Traffic Server is running inside the cluster, no configuration is required;
it will pick up its service account details automatically.

Otherwise, copy `kubernetes.config.example` to the Traffic Server configuration
directory as `kubernetes.config` and edit it for your site.

Debugging
---------

To debug problems with the plugin, enable the debug tags `kubernetes` (for the
plugin itself) or `watcher` (for the Kubernetes API code).

Use with multiple Ingress controllers
-------------------------------------

The TS Ingress controller will handle any Ingress resource which does not have
an Ingress class set, or where the Ingress class is set to "trafficserver".

If this is the only Ingress controller you are using, you do not need to set the
Ingress class; TS will handle all ingress resources.

Otherwise, to ensure an Ingress resource is only handled by this controller, set
the class:

```
metadata:
  annotations:
    kubernetes.io/ingress.class: "trafficserver"
```

To change the Ingress classes that TS will handle, set `ingress_classes` in
`kubernetes.config` (or the `$TS_INGRESS_CLASSES` environment variable) to a
whitespace-separate list of values, e.g. `"trafficserver ts-staging"`.  This
can be used to run multiple copies of the TS Ingress controller in one cluster.
If you do this, the `trafficserver` class will not be handled unless you
explicitly include it in the list.

For more information, see
[Using Multiple Ingress Controller](https://github.com/nginxinc/kubernetes-ingress/tree/master/examples/multiple-ingress-controllers)
in the Kubernetes documentation.

Use with kube-lego
------------------

kube-lego currently
[doesn't support](https://github.com/jetstack/kube-lego/issues/189) any
Ingress controllers other than nginx and GCE.  To use the TS Ingress controller
with kube-lego, you should tell it to handle the `"nginx"` Ingress class in
`kubernetes.config`:

```
ingress_classes: trafficserver nginx
```

Or by setting `$TS_INGRESS_CLASSES` to `"trafficserver nginx"`.

Ingress annotations
-------------------

The behaviour of an Ingress can be configured by setting annotations on the
resource.  Annotations beginning with `ingress.kubernetes.io` are standard
annotations supported by most Ingress controllers; those beginning with
`ingress.torchbox.com` are specific to the Traffic Server Ingress controller.

* `ingress.kubernetes.io/rewrite-target`: if set to a string, the portion of the
  request path matched by the Ingress `path` attribute will be replaced with
  this string.  This has no effect on an Ingress without a `path` set.

* `ingress.kubernetes.io/app-root`: if set to a path prefix, and the request URI
  does not begin with that prefix, then a redirect will be returned to this
  path.  This can be used for applications which sit in a subdirectory rather
  than at the root.

* `ingress.torchbox.com/follow-redirects`: if `"true"`, Traffic Server will
  follow 3xx redirect responses and serve the final response to the client.
  If the redirect destination is cached, it will be cached with the cache key
  of the original request.  Redirects will only be followed to other Ingress
  resources, not to arbitrary destinations (but see below about proxying to
  external resources).

* `ingress.torchbox.com/preserve-host`: if `"false"`, set the `Host` header
  in the request to the backend name (e.g., the pod name), instead of the
  original request host.

TLS
---

TLS keys and certificates are taken from Kubernetes Secret resources according
to `tls` attribute of each Ingress resource.  TLS Server Name Indication support
is required for this to work; clients without SNI support will receive a TLS
negotiation error.

If you don't want to use Kubernetes for TLS, set `tls: false` in
`kubernetes.config`.  You will need to provide TLS configuration some other way,
like `ssl_multicert.config` or the `ssl-cert-loader` plugin, or else terminate
TLS before traffic reaches Traffic Server.

By default, non-TLS HTTP requests to an Ingress host with TLS configured will
be 301 redirected to HTTPS.  To disable this behaviour, set the
`ingress.kubernetes.io/ssl-redirect` annotation to `false`.

To force a redirect to HTTPS even when TLS is not configured on the Ingress, set
the `ingress.kubernetes.io/force-ssl-redirect` annotation to `true`.  This will
not work unless you are offloading TLS termination in front of Traffic Server.

Usually, communication between Traffic Server and backends (e.g. pods) is via
non-TLS HTTP, even if the request was made over HTTPS.  To use HTTPS to
communicate with the backend, set the `ingress.kubernetes.io/secure-backends`
annotation to `true`.  This is not very useful when the backend is a pod,
because TS connects to the pod by its IP address, and it's extremely unlikely
the pod will have a TLS certificate for that IP address.  However, this can be
useful when using external proxying (described below).

A better method to secure traffic between Traffic Server and pods is to use a
network CNI plugin that supports encryption, such as Weave Net.

To enable HTTP Strict Transport Security (HSTS), set the
`ingress.torchbox.com/hsts-max-age` annotation on the Ingress to the HSTS
max-age time in seconds.  To be useful, this should be set to at least six
months (15768000 seconds), but you should start with a lower value and gradually
increase it.  Do not set it to a large value without testing it first, because,
by design, it cannot be turned off for browsers that already saw the HSTS
header until the max-age expires.

HSTS headers are per-hostname, not per-host.  Therefore, `hsts-max-age` can only
be set on the Ingress that includes the root path for a particular hostname
(i.e., where the Ingress rule has no `path` attribute).

To apply HSTS to subdomains as well, set the
`ingress.torchbox.com/hsts-include-subdomains` annotation.

Caching
-------

Traffic Server will cache HTTP responses according to their `Cache-Control`
and/or `Expires` headers.  `Cache-Control` is the recommended method of
configuring caching, since it's much more flexible than `Expires`.

Ingress annotations can be used to configure caching.  To disable caching
entirely, set the `ingress.torchbox.com/cache-enable` annotation to `false`.

You can purge individual URLs from the cache by sending an HTTP `PURGE` request
to Traffic Server.  To make this easy to do from pods, create a Service for the
TS pod.  The PURGE request should look like this:

```
PURGE http://www.mysite.com/mypage.html HTTP/1.0
```

Unfortunately, this doesn't work very well when multiple copies of TS are
running, since there's no simple way for an application to retrieve the list of
TS instances.  We plan to release our internal purge multiplexor service called
"multipurger" which solves this problem.

Occasionally, you might want to clear the cache for an entire domain, for
example if some boilerplate HTML has changed that affects all pages.  To do this,
set the `ingress.torchbox.com/cache-generation` annotation to a non-zero
integer.  This changes the cache generation for the Ingress; any objects cached
with a different generation are no longer visible, and have been effectively
removed from the cache.  Typically the cache generation would be set to the
current UNIX timestamp, although any non-zero integer will work.

### Ignoring URL parameters for caching

When a page is cached, its URL parameters are stored in the cache to ensure that
a request with different URL parameters returns the correct content.  For
example, the URL:

```
http://www.mysite.com/listings/?page=1
```

should be cached differently from the URL:

```
http://www.mysite.com/listings/?page=2
```

Usually this is what you want and no additional configuration is required.
However, sometimes clients may request pages with additional URL parameters
which do not affect page content.  A good example of this is marketing tracking
parameters like `utm_medium` which are used by JavaScript on the page to
identify traffic sources, but do not affect the page content at all.  Because
these URL parameters do not affect page content, they should not be considered
when caching.  (The JavaScript tracking code will run anyway, so no data is
lost.)

There are two approaches to configuring this: either you can set a list of URL
parameters which should be ignored when caching (which is the safest method),
or you can set a whitelist of parameters, where any parameters not in the
list will be ignored.

To exclude a set of parameters from caching, set the
`ingress.torchbox.com/cache-ignore-params` annotation on the Ingress:

```
    ingress.torchbox.com/cache-ignore-params: "utm_* source_id"
```

The value should be a list of UNIX globs (`*`, `?` and `[...]` are supported);
any matching query parameters will be ignored for caching.

To set a whitelist of URL parameters, set the
`ingress.torchbox.com/cache-whitelist-params` annotation:

```
    ingress.torchbox.com/cache-whitelist-params: "page view include_id_*"
```

The format is the same as `cache-ignore-params`, but the meaning is reversed:
any URL parameter not matched will be ignored.

When using either of these annotations, you probably also want to set
`ingress.torchbox.com/cache-sort-params: "true"`, which will cause the URL
parameters to be lexically sorted; these means that a request for `/?a=1&b=2`
will be cached the same as a request for `/?b=2&a=1`, improving cache hit rate
across clients.

These annotations also change the query string sent to the application.  This is
to ensure the application doesn't accidentally vary the page content based on a
query parameter that has been ignored for caching.

Authentication
--------------

### Password authentication

To enable password authentication, set the `ingress.kubernetes.io/auth-type`
annotation on the Ingress to `basic`, and `ingress.kubernetes.io/auth-secret`
to the name of a secret which contains an htpasswd file as the `auth` key.  You
can create such a secret with `kubectl`:

```
$ kubectl create secret generic my-auth --from-file=auth=my-htpasswd
```

Optionally, set `ingress.kubernetes.io/auth-realm` to the basic authentication
realm, which is displayed in the password prompt by most browsers.

Most common password hash schemes are supported, including DES, MD5 (`$1$` and
`$apr1$`), bcrypt (`$2[abxy]$`), SHA-256 (`$5$`) and SHA-512 (`$6$`), and four
RFC2307-style hashes: `{PLAIN}`, `{SHA}`, `{SSHA}` and `{CRYPT}` (the first
three of which are also supported by nginx; `{CRYPT}` is supported by OpenLDAP,
but is somewhat redundant since it's handled by simply removing the `{CRYPT}`
prefix and treating it as a normal crypt hash).

Security-wise, although the MD5 schemes are extremely weak as password hashes,
they are probably fine for any situation where htpasswd-based authentication is
in use.  The primary security improvement in newer algorithms (e.g. bcrypt and
SHA-2) is they are slower, which increases the time required to perform an
offline brute force attack; however, this also increases the time required to
_check_ the password, which leads to unacceptable delays on typical HTML page
loads.

For example, if you use a bcrypt configuration that takes 200ms to check one
hash, and you load an HTML page with 20 assets, then you will spend 4 seconds
doing nothing but waiting for authentication.  If multiple users are loading
pages at the same time, then things will be even slower once you run out of
CPUs.

If you need stronger password security than MD5, you should stop using HTTP
basic authentication and use another authentication method (like Cookie-based
authentication) instead.

### IP address authentication

To enable IP authentication, set the
`ingress.kubernetes.io/whitelist-source-range` annotation to a comma-delimited
list of IP addresses or networks, for example `"127.0.0.0/8,::1/128"`.

When both IP authentication and password authentication are configured on the
same ingress, you can set the `ingress.torchbox.com/auth-satisfy` annotation to
either `any` or `all`:

* `any` will permit the request if either the IP is present in
  `whitelist-source-range` or if the client provides valid basic authentication;
  otherwise the request will be denied with HTTP 401 Unauthorized.

* `all` will permit the request if the client IP is present in
  `whitelist-source-range` *and* the client also provides valid basic
  authentication.  If the client IP address is not in the address list, the
  request will be denied with HTTP 403 Forbidden.  If the IP address is present
  but the request did not contain valid basic authentication, the request will
  be denied with HTTP 401 Unauthorized.

To prevent accidental misconfiguration, the default value is `all`.

Note: the IP list is implemented as a simple linked list, rather than a more
efficient data structure such as a radix tree.  This means that the lookup time,
and consequently the overall request time, will increase linearly as the number
of entries in the list increases.

This decision was made because a linked list is a simpler data structure, and
therefore performs better with a small number of entries even though performance
is worse with a larger list.  This trade-off will only become noticeable if you
have hundreds or thousands of entries in the address list, which is very
unlikely in real-world deployments.  (For one thing, it would be extremely
cumbersome to manage such a large list as an annotation.)

If you require support for such a large number of addresses in a single Ingress,
please let us know via a Github issue.

External proxying
-----------------

Sometimes, you might want to proxy traffic to a service that doesn't run as a
Kubernetes pod.  This can be used to expose external services via an Ingress,
and to allow the `follow-redirects` annotation to access external resources.

### External proxying via IP address

To proxy requests to a particular IP address or a set of IP address, create a
`Service` resource without a selector, and create its associated `Endpoints`
resource:

```
kind: Service
apiVersion: v1
metadata:
  name: external-service
spec:
  ports:
  - protocol: TCP
    port: 80

---

kind: Endpoints
apiVersion: v1
metadata:
  name: external-service
subsets:
- addresses:
  - ip: 1.2.3.4
  ports:
  - port: 80
```

You can now define an Ingress to route traffic to this service:

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: external-ingress
spec:
  rules:
  - host: external.example.com
    http:
      paths:
      - backend:
          serviceName: external-service
          servicePort: 80
```

Traffic Server will now route requests for http://external.example.com/ to your
external service at IP address 1.2.3.4.

### External proxying via hostname

To proxy to an external hostname, create a `Service` resource of type
`ExternalName`:

```
kind: Service
apiVersion: v1
metadata:
  name: external-service
spec:
  type: ExternalName
  externalName: my-external-backend.example.com
```

Do not configure an `Endpoints` resource.  Create an Ingress for this Service:

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: external-ingress
  annotations:
    ingress.torchbox.com/preserve-host: "false"
spec:
  rules:
  - host: external.example.com
    http:
      paths:
      - backend:
          serviceName: external-service
          servicePort: 80
```

Now requests for http://external.example.com will be proxied to
http://my-external-backend.example.com.

When using an ExternalName Service, the `servicePort` must be an integer;
named ports are not supported.

In most cases, you will want to set the `preserve-host` annotation to `"false"`
so that the external service sees the hostname it's expecting, rather than the
hostname in the client request.

### External proxying and TLS

By default, even if a request uses TLS, it will be proxied to the external
backend via HTTP.  To use TLS for the backend, set an annotation on the Ingress:
`ingress.kubernetes.io/secure-backends: "true"`.  This is not very useful for
external IP addresses, because it's unlikely the backend will have a TLS
certificate for its IP address, but it will work well with `ExternalName`
services.

For TLS to work, remember to set `servicePort` to `443` (or some other suitable
value).

Planned features
----------------

A feature being listed here indicates we are interested in implementing it, but
provides no guarantee that it will be implemented within any particular time
frame, or ever.

* TLS client certificate authentication.
* Client session affinity
* Proxy protocol
* Cross-Origin Resource Sharing
* Rate limiting
* SSL passthrough
* Global / default configuration
* Per-ingress gzip configuration
* HSTS preload support (in any case, rewrite the HSTS support as it will be
  removed from TS core in some later release)
* Per-Ingress timeout configuration
* HTTP/2 server push
* Custom error bodies
* Improve API watch support by first retrieving all objects, then watching with
  resourceVersion.

Support
-------

Please open a [Github issue](https://github.com/torchbox/k8s-ts-ingress/issues)
for questions or support, or to report bugs.

Release history
---------------

* 1.0.0-alpha5 (unreleased):
    * Incompatible change: The `ingress.torchbox.com/auth-address-list`
        annotation was renamed to `ingress.kubernetes.io/whitelist-source-range`,
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

License
-------

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

`strmatch.c` is copyright (c) 1989, 1993, 1994 The Regents of the University
of California, based on code written by Guido van Rossum.

`crypt_md5.c` was written by Poul-Henning Kamp, and is released under the
"beer-ware" license.

`crypt_sha256.c` and `crypt_sha512.c` were written by Ulrich Drepper, and are
released into the public domain.

`hash.c` contains code written by Landon Curt Noll, which is released into the
public domain.

`base64.c` is copyright (c) 2011-2017 Felicity Tarnell.
