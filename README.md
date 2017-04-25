Apache Traffic Server ingress controller for Kubernetes
=======================================================

**WARNING: This is pre-alpha code, do not use it in production.**

This is a Kubernetes ingress controller plugin for
[Apache Traffic Server](https://trafficserver.apache.org/).  It allows Traffic
Server to act as an ingress controller for Kubernetes clusters, routing incoming
requests to pods while providing TLS termination, caching, ESI and other standard
Traffic Server features.

This implementation replaces our [previous implementation](https://github.com/torchbox/trafficserver-ingress-controller),
which generated TS `remap.config` configuration using an external script.

The plugin is only supported with Traffic Server 7.0.  It may work with 6.x
versions, but has not been tested.  It definitely won't work with 5.x or older
versions without modifications, as the plugin API has changed.

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

Run `make install` to install the plugin, or copy the `kubernetes.so` to the
Traffic Server plugin directory (e.g.
`/usr/local/trafficserver/libexec/trafficserver`).  Edit `plugin.config` to
load the plugin.

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

SSLv3 (and earlier) is not supported.

TLS support currently has several limitations:

* Specifying custom Diffie-Hellman parameters (dhparams) is not supported.
* OCSP is not supported.
* Multiple certificates per Ingress (e.g. Elliptic Curve and RSA certificates)
  is not supported.
* TLS session resumption across multiple servers is not supported.
* TLS client certification authentication is not supported.
* HTTP Strict Transport Security is not supported (although applications which
  send their own HSTS headers will work fine).
* TLS connections to origin servers (pods) is not supported.
* The following Traffic Server TLS configuration options are supported; all
  other TLS configuration is ignored.
    * `proxy.config.ssl.TLSv1`
    * `proxy.config.ssl.TLSv1_1`
    * `proxy.config.ssl.TLSv1_2`
    * `proxy.config.ssl.server.honor_cipher_order`
    * `proxy.config.ssl.server.cipher_suite`

If you don't want to use Kubernetes for TLS, you can configure your own TLS
certificates in `ssl_multicert.config` or though some other mechanism (e.g.
the `ssl-cert-loader` plugin).  In that case, TLS works exactly as it would
if Kubernetes was not involved.

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
