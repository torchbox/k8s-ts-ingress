# Using TLS

## Configuration

TLS keys and certificates are taken from Kubernetes Secret resources according
to `tls` attribute of each Ingress resource.  TLS Server Name Indication support
is required for this to work; clients without SNI support will receive a TLS
negotiation error.

If you don't want to use Kubernetes for TLS, set `tls: false` in
`kubernetes.config` or set the `$TS_TLS` environment variable to `"false"`.
You will need to provide TLS configuration some other way, like
`ssl_multicert.config` or the `ssl-cert-loader` plugin, or else terminate TLS
before traffic reaches Traffic Server.

By default, non-TLS HTTP requests to an Ingress host with TLS configured will
be 301 redirected to HTTPS.  To disable this behaviour, set the
`ingress.kubernetes.io/ssl-redirect` annotation to `false`.

To force a redirect to HTTPS even when TLS is not configured on the Ingress, set
the `ingress.kubernetes.io/force-ssl-redirect` annotation to `"true"`.  This
will not work unless you are offloading TLS termination in front of Traffic
Server.

## Connecting to pods via HTTPS

Usually, communication between Traffic Server and backends (e.g. pods) is via
non-TLS HTTP, even if the request was made over HTTPS.  To use HTTPS to
communicate with the backend, set the `ingress.kubernetes.io/secure-backends`
annotation to `"true"`.  This is not very useful when the backend is a pod,
because TS connects to the pod by its IP address, and it's extremely unlikely
the pod will have a TLS certificate for that IP address.  However, this can be
useful when using external proxying (described below).

A better method to secure traffic between Traffic Server and pods is to use a
network CNI plugin that supports encryption, such as Weave Net.

## HSTS

To enable HTTP Strict Transport Security (HSTS), set the
`ingress.kubernetes.io/hsts-max-age` annotation on the Ingress to the HSTS
max-age time in seconds.  To be useful, this should be set to at least six
months (15768000 seconds), but you should start with a lower value and gradually
increase it.  Do not set it to a large value without testing it first, because,
by design, it cannot be turned off for browsers that already saw the HSTS
header until the max-age expires.

HSTS headers are per-hostname, not per-host.  Therefore, `hsts-max-age` can only
be set on the Ingress that includes the root path for a particular hostname
(i.e., where the Ingress rule has no `path` attribute).

To apply HSTS to subdomains as well, set the
`ingress.kubernetes.io/hsts-include-subdomains` annotation.

## kube-lego

kube-lego, a Kubernetes controller that automatically provisions TLS
certificates using an ACME provider such as Let's Encrypt, currently
[doesn't support](https://github.com/jetstack/kube-lego/issues/189) any
Ingress controllers other than nginx and GCE.  To use the TS Ingress controller
with kube-lego, you should tell it to handle the `"nginx"` Ingress class,
either in `kubernetes.config`:

```
ingress_classes: trafficserver nginx
```

Or by setting the `TS_INGRESS_CLASSES` environment variabe to
`"trafficserver nginx"`.

Then configure kube-lego as if you were using the nginx Ingress controller.
