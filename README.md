Apache Traffic Server ingress controller for Kubernetes
=======================================================

This is a Kubernetes ingress controller using Apache Traffic Server.
It uses [our Docker image](https://github.com/torchbox/docker-trafficserver)
of Traffic Server 7.0.

We have been using this internally for several months without issues, but make
no guarantees about its suitability for production.  Please report any problems
you run into.

To enable it as a Deployment, exposed as port 30080 (http) and 30443 (https)
on nodes:

    $ kubectl apply -f trafficserver-ds.yml

You will need some sort of external load balancer to distribute incoming
requests to the controller. 

It will poll for changes to ingress resources every 30 seconds.

The current TS configuration is very opinionated about how caching and proxying
should work.  PRs to make it more configurable are welcome.  (Either via
environment variables, or by attributes on the ingress resource.)

For persistent cache storage, mount a volume on /var/lib/trafficserver.
This can be an emptyDir; necessary files will be created at startup.

Configuration
-------------

Environment variables:

* `TS_CACHE_SIZE`: Size of the on-disk cache file to create, in megabytes.
* `ROUTE_DEIS`: If set, Traffic Server will router Deis applications,
replacing the Deis router.  (Experimental and unsupported; this will likely
be removed at some point in the future, as we no longer use Deis.)

In addition, any TS configuration (records.config) setting can be
overridden in the environment:

https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.config.en.html#environment-overrides

SSL
---

SSL is supported via `tls` attributes on the ingress.  This supports
automatic certificate issuance when used with a service like `kube-lego`.
