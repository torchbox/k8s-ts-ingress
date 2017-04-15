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

Currently, TLS is not supported.

For persistent cache storage, mount a volume on /var/lib/trafficserver.
This can be an emptyDir; necessary files will be created at startup.

Configuration
-------------

Environment variables:

* `TS_CACHE_SIZE`: Size of the on-disk cache file to create, in megabytes.

In addition, any TS configuration (records.config) setting can be
overridden in the environment:

https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.config.en.html#environment-overrides

TLS
---

Currently, TLS (SSL) is not supported in this implementation.
