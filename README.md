Apache Traffic Server ingress controller for Kubernetes
=======================================================

**WARNING: This is pre-alpha code, do not use it in production.**

This is a Kubernetes ingress controller plugin for
[Apache Traffic Server](https://trafficserver.apache.org/).  It allows Traffic
Server to act as an ingress controller for Kubernetes clusters, routing incoming
requests to pods while providing caching, ESI and other standard Traffic Server
features.

This implementation replaces our [previous implementation](https://github.com/torchbox/trafficserver-ingress-controller),
which generated TS remap configuration using an external script.  Compared to
the old version, this implementation responds to changes faster, handles pod
failure better, and reduces system load due to not constantly reloading TS.
In future, running the controller as a plugin will make it easier to add
additional features.

For persistent cache storage, mount a volume on /var/lib/trafficserver.
This can be an emptyDir; necessary files will be created at startup.

Building
--------

Building the plugin isn't necessary if you use the pre-built Docker image.

Build the plugin:

```
$ make
```

Installation
------------

Installing the plugin isn't necessary if you use the pre-built Docker image.

The plugin comes in two parts:

* `kubernetes_remap.so` handles remapping incoming requests to the Kubernetes
  pods based on Ingress rules.
* `kubernetes_ssl.so` handles certificates for incoming TLS connections based
  on Kubernetes secrets referenced from Ingress rules.

You need both parts to have a functional Ingress controller, although you can
omit `kubernetes_ssl.so` if you don't want to use Ingress for TLS, or you're
doing TLS offloading somewhere else.

Copy both plugins to the Traffic Server plugin directory (e.g.
`/usr/local/trafficserver/libexec/trafficserver`).

Configure `kubernetes_remap.so` as a remap plugin:

```
map / http://localhost @plugin=kubernetes_remap.so @pparam=--kubeconfig=/path/to/my/kubeconfig
```

Configure `kubernetes_ssl.so` in `plugin.config`:

```
kubernetes_ssl.so --kubeconfig=/path/to/my/kubeconfig
```

If Traffic Server is running in-cluster, you can omit the `--kubeconfig`
arguments.

The remap source URL can be set to whatever you want; using `/` causes the plugin
to handle all URLs.

Configuration
-------------

If you're using the pre-built Docker image, you can set the following environment
variables to configure Traffic Server:

* `TS_CACHE_SIZE`: Size of the on-disk cache file to create, in megabytes.

In addition, any TS configuration (records.config) setting can be
overridden in the environment:

https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.config.en.html#environment-overrides
