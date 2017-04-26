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

Building
--------

Requirements:

* A working C compiler and `make` utility.
* json-c library
* OpenSSL (or a compatible TLS library, e.g. LibreSSL)

Build and install the plugin:

```
$ ./configure [--with-tsxs=/path/to/trafficserver/bin/tsxs]
$ make
# make install
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

TLS
---

TLS keys and certificates are taken from Kubernetes Secret resources according
to the Ingress controller specification.  TLS Server Name Indication support is
required; clients without SNI support will not work.  This is not considered
a deficiency, since all current TLS clients support SNI.

By default, non-TLS HTTP requests to an Ingress host with TLS configured will
be 301 redirected to HTTPS.  To disable this behaviour, use the `ssl-redirect`
annotation described below.

If you don't want to use Kubernetes for TLS, set `tls: false` in
`kubernetes.config`, then configure your own TLS certificates in
`ssl_multicert.config` or though some other mechanism (e.g. the `ssl-cert-loader`
plugin).  In that case, TLS works exactly as it would if Kubernetes was not
involved.

Debugging
---------

To debug problems with the plugin, enable the debug tags `kubernetes` (for the
plugin itself) or `watcher` (for the Kubernetes API code).

Docker configuration
--------------------

If you're using the pre-built Docker image, you can set the following environment
variables to configure Traffic Server:

* `TS_CACHE_SIZE`: Size of the on-disk cache file to create, in megabytes.

In addition, any TS configuration (records.config) setting can be
overridden in the environment:

https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.config.en.html#environment-overrides

For persistent cache storage, mount a volume on `/var/lib/trafficserver`.
This can be a persistent volume or an emptyDir; any missing necessary files,
including the cache store, will be created at startup.

Caching
-------

Traffic Server will cache HTTP responses according to their `Cache-Control`
and/or `Expires` headers.  `Cache-Control` is the recommended method of
configuring caching, since it's much more flexible than `Expires`.

Ingress annotations, described below, can be used to configure caching.  In
particular, to disable caching entirely, use the `cache-enable` annotations.

Ingress annotations
-------------------

The behaviour of an Ingress can be configured by setting annotations on the
resource.  Annotations beginning with `ingress.kubernetes.io` are standard
annotations supported by most Ingress controllers; those beginning with
`ingress.torchbox.com` are specific to the Traffic Server Ingress controller.

### TLS

* `ingress.kubernetes.io/ssl-redirect`: if `"false"`, do not redirect HTTP
  requests to HTTPS, even if the Ingress has TLS configured.

* `ingress.kubernetes.io/force-ssl-redirect`: if `"true"`, redirect HTTP
  requests to HTTPS even if the Ingress does not have TLS configured.

* `ingress.kubernetes.io/secure-backends`: if `"true"`, use TLS connections to
  the backend.  This is generally not useful when connecting to pods, but can
  be useful for external proxying (described below).

* `ingress.torchbox.com/hsts-max-age`: if set to a non-zero integer value,
  TLS responses will include an HTTP Strict-Transport-Security header with the
  given age in seconds.  To be useful, this should be set to at least six
  months (15768000 seconds).  **NOTE**: While this can be configured for a
  particular hostname on some paths and not others, once a browser sees the HSTS
  header it will apply that to *all* paths for that hostname, not just the ones
  where the HSTS header was set.  You cannot enable HSTS for a subset of paths.

* `ingress.torchbox.com/hsts-include-subdomains`: if `"true"`, HSTS headers
  will set `includeSubdomains`.

### URL rewriting

* `ingress.kubernetes.io/rewrite-target`: if set to a string, the portion of the
  request path matched by the Ingress `path` attribute will be replaced with
  this string.  This has no effect on an Ingress without a `path` set.

* `ingress.kubernetes.io/app-root`: if set to a path prefix, and the request URI
  does not begin with that prefix, then a redirect will be returned to this
  path.  This can be used for applications which sit in a subdirectory rather
  than at the root.

### Caching

* `ingress.torchbox.com/cache-enable`: if `"false"`, do not cache responses
  even if the response has `Cache-Control` headers.

* `ingress.torchbox.com/cache-generation`: a non-zero integer used to set the
  cache generation for this Ingress.  Changing the cache generation has the
  effect of clearing the HTTP cache for that Ingress.  Typically this would be
  set to the current timestamp to clear the cache when large changes are made
  to the site.

### Miscellaneous

* `ingress.torchbox.com/follow-redirects`: if `"true"`, Traffic Server will
  follow 3xx redirect responses and serve the final response to the client.
  If the redirect destination is cached, it will be cached with the cache key
  of the original request.  Redirects will only be followed to other Ingress
  resources, not to arbitrary destinations.

* `ingress.torchbox.com/preserve-host`: if `"false"`, set the `Host` header
  in the request to the backend name (e.g., the pod name), instead of the
  original request host.

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

Support
-------

Please open a [Github issue](https://github.com/torchbox/k8s-ts-ingress/issues)
for questions or support, or to report bugs.


License
-------

This plugin was developed by Felicity Tarnell <felicity@torchbox.com> for
[Torchbox](https://torchbox.com).  Copyright (c) 2016-2017 Torchbox Ltd.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
