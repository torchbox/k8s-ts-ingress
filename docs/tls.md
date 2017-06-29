# Using TLS

## Configuration

TLS keys and certificates are taken from Kubernetes Secret resources according
to the `tls` attribute of each Ingress resource.  See the
[Ingress documentation](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
for details on how to configure TLS.

TLS Server Name Indication support is required for TLS to work; clients without
SNI support will receive a TLS negotiation error.  There is no default
certificate for non-SNI-capable clients.

If you don't want to use Kubernetes for TLS, set `tls: false` in
`kubernetes.config` or set the `$TS_TLS` environment variable to `"false"`.
You will need to provide TLS configuration some other way, like
`ssl_multicert.config` or the `ssl-cert-loader` plugin, or else terminate TLS
before traffic reaches Traffic Server.

## Redirecting HTTP to HTTPS

By default, insecure HTTP requests to an Ingress which has TLS configured will
be redirected to HTTPS with an HTTP 301 response.  To disable this behaviour,
set the `ingress.kubernetes.io/ssl-redirect` annotation to `false`.

This redirect only happens when a valid TLS certificate could be loaded for the
Ingress, so if you're using kube-lego and it hasn't issued a certificate yet,
the redirect won't be done; this allows kube-lego to do the initial domain
validation correctly.

To force a redirect to HTTPS even when TLS is not configured on the Ingress, set
the `ingress.kubernetes.io/force-ssl-redirect` annotation to `"true"`.  This
will not work unless you are offloading TLS termination in front of Traffic
Server.

## Connecting to pods via HTTPS

Usually, communication between Traffic Server and backends (e.g. pods) is via
insecure HTTP, even if the request was made over HTTPS.  To use HTTPS for
communicate with the backend, set the `ingress.kubernetes.io/secure-backends`
annotation to `"true"`.  This is not very useful when the backend is a pod,
because TS connects to the pod by its IP address, and it's extremely unlikely
the pod will have a TLS certificate for that IP address.  However, this can be
useful when using [external proxying](external.md).

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

HSTS headers are per-hostname, not per-path.  Therefore, `hsts-max-age` can only
be set on the Ingress that includes the root path for a particular hostname
(i.e., where the Ingress rule has no `path` attribute).

To apply HSTS to subdomains as well, set the
`ingress.kubernetes.io/hsts-include-subdomains` annotation.

## Configuring the TLS cypher list

You cannot configure the cypher list on the Ingress level; this was judged to be
too risky, as users are likely to set a cypher list and not keep it up to date
with changes in best practice.  (If you require this feature, please open a
[Github issue](https://github.com/torchbox/k8s-ts-ingress/issues).)

To configure the global cypher list, set `proxy.config.ssl.server.cipher_suite`
in the TS `records.config` file to an OpenSSL cypher string, or set the
`$PROXY_CONFIG_SSL_SERVER_CIPHER_SUITE` environment variable:

```
PROXY_CONFIG_SSL_SERVER_CIPHER_SUITE=ECDH+AES:DH+AES:RSA+AES:!aNULL:!MD5:!DSS
```

## Configuring the minimum TLS version

To set the minimum TLS version on an Ingress, set the
`ingress.kubernetes.io/tls-minimum-version` annotation:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/tls-minimum-version: "1.1"
```

Accepted values are `"1.0"`, `"1.1"` and `"1.2"`.  TLS 1.3 is not supported.

Due to limitations in OpenSSL and Traffic Server, this will not work correctly
if you have configured TLS certificates in `ssl_multicert.config`.

To configure the global minimum TLS version, set one or more of the following
environment variables:

* `PROXY_CONFIG_SSL_TLSV1=0`: disable TLS 1.0
* `PROXY_CONFIG_SSL_TLSV1_1=0`: disable TLS 1.1
* `PROXY_CONFIG_SSL_TLSV1_2=0`: disable TLS 1.2

## Using kube-lego

[kube-lego](https://github.com/jetstack/kube-lego) is a Kubernetes controller
that automatically provisions TLS certificates using an ACME provider such as
Let's Encrypt.  It is ideal for test or staging environments (or even production
environments when domain-validated TLS certificates are sufficient), but it
currently [doesn't support](https://github.com/jetstack/kube-lego/issues/189)
any Ingress controllers other than nginx and GCE.

To use the TS Ingress controller with kube-lego, you should configure kube-lego
as if you were using the nginx Ingress controller, then tell TS to handle the
`"nginx"` Ingress class, either by setting the environment variable
`$TS_INGRESS_CLASSES` to `trafficserver nginx`, or in `kubernetes.config`:

```
ingress_classes: trafficserver nginx
```
