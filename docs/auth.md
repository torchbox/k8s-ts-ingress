# Authentication

Authentication restricts who can request a particular page.  Authenticatian can
be done using HTTP basic authentication, where the client sends a username and
password in the request; by IP address, where only certain IP addresses are
permitted to request the content; or by a combination of both.

## Password authentication

To enable password authentication, set the `ingress.kubernetes.io/auth-type`
annotation on the Ingress to `basic`, and `ingress.kubernetes.io/auth-secret`
to the name of a secret which contains an htpasswd file as the `auth` key:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/auth-type: basic
    ingress.kubernetes.io/auth-secret: mysecret
```

You can create the necessary secret from an existing htpasswd file with `kubectl`:

```sh
$ kubectl create secret generic mysecret --from-file=auth=my-htpasswd
```

Optionally, set `ingress.kubernetes.io/auth-realm` to the basic authentication
realm, which is displayed in the password prompt by most browsers.

Most common password hash schemes are supported, including DES, MD5 (`$1$` and
`$apr1$`), bcrypt (`$2[abxy]$`), SHA-256 (`$5$`) and SHA-512 (`$6$`), and four
RFC2307-style hashes: `{PLAIN}`, `{SHA}`, `{SSHA}` and `{CRYPT}` (the first
three of which are also supported by nginx).

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

## IP address authentication

To enable IP authentication, set the
`ingress.kubernetes.io/whitelist-source-range` annotation to a comma-delimited
list of IP addresses or networks, for example `"127.0.0.0/8,::1/128"`.

When both IP-based and password-authentication are configured on the same
ingress, you can set the `ingress.kubernetes.io/auth-satisfy` annotation to
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

**Important**: IP address authentication requires that Traffic Server knows the
original IP address of the client making the request.  If TS is serving requests
directly, or sits behind a transparent load balancer that preserves the client
IP address (such as an Azure service, a GCE network load balancer, or Linux LVS
in some configurations), then this will be the case; otherwise, it will see all
requests as coming from the load balancer's internal IP address, and
authentication will not be effective.  We plan to address this limitation in a
future release, using either the `X-Forwarded-For` header field, or the
so-called Proxy Protocol.

Scalability note: The IP list is implemented as a simple linked list, rather
than a more efficient data structure such as a radix tree.  This means that the
lookup time, and consequently the overall request time, will increase linearly
as the number of entries in the list increases.

This decision was made because a linked list is a simpler data structure, and
therefore performs better with a small number of entries even though performance
is worse with a larger list.  This trade-off will only become noticeable if you
have hundreds or thousands of entries in the address list, which is very
unlikely in real-world deployments.  (For one thing, it would be extremely
cumbersome to manage such a large list as an annotation.)

If you require support for such a large number of addresses in a single Ingress,
please let us know via a Github issue.
