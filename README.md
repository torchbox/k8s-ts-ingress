Apache Traffic Server ingress controller for Kubernetes
=======================================================

This is a Kubernetes ingress controller using Apache Traffic Server.
Currently, it is only suitable for testing, and uses a development
version of TS 7.0.

To enable it:

    $ kubectl apply -f trafficserver.yml

It will poll for changes to ingress resources every 30 seconds.

The current TS configuration is very opinionated about how caching
and proxying should work.  PRs to make it more configurable are
welcome.  (Either via environment variables, or by attributes on
the ingress resource.)

For persistent cache storage, mount a volume on /var/lib/trafficserver.
This can be an emptyDir; necessary files will be created at startup.

Configuration
-------------

Environment variables:

* `TS_CACHE_SIZE`: Size of the cache file to create, in megabytes.
* `ROUTE_DEIS`: If set, Traffic Server will router Deis applications,
replacing the Deis router.

In addition, any TS configuration (records.config) setting can be
overridden in the environment:

https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.config.en.html#environment-overrides

SSL
---

SSL is supported via `tls` attributes on the ingress.  This supports
automatic certificate issuance when used with a service like `kube-lego`.
