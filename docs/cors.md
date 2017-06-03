# Configuring Cross-Origing Resource Sharing

CORS is a method to permit cross-origin HTTP requests in JavaScript, i.e.
requests made by JS running on one domain to a page on a different domain.
This is usually disallowed for security reasons (it could allow one page to
send requests using the user's credentials to another page); CORS provides a
way to safely permit such requests.

For more information on CORS, see the documentation on the
[Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS).

There are two ways to configure CORS: either your application can send CORS
headers itself, or you can configure the Ingress resource to do so for you.
If your application is handling CORS itself, you do not need any of the
configuration described here.

## CORS configuration

To enable cross-origin requests from any domain, set the
`ingress.kubernetes.io/enable-cors` annotation on the Ingress resource:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/enable-cors: "true"
```

This will allow requests from any origin, without credentials, for the CORS
basic methods (GET, POST and HEAD).  This is generally sufficient to permit
cross-origin loading of resources (such as fonts) without compromising the
security of the application.

If you want to restrict requests to a set of origins, you can set the
`cors-origins` annotations:

```yaml
  annotations:
    ingress.kubernetes.io/enable-cors: "true"
    ingress.kubernetes.io/cors-origins: "http://example.com http://example.org"
```

This would allow cross-origin requests from the two listed origins, but no
others.

If you want to permit requests with credentials, you can set the `cors-credentials`
annotation:

```yaml
  annotations:
    ingress.kubernetes.io/enable-cors: "true"
    ingress.kubernetes.io/cors-origins: "http://example.com http://example.org"
    ingress.kubernetes.io/cors-credentials: "true"
```

This will permit requests with credentials (such as Cookie headers); be very
careful with this, as it essentially allows any of the listed origins to make
requests using the user's credentials.  If you use `cors-credentials`, you must
also set `cors-origins`; you cannot allow requests with credentials from any
origin.

By default, requests are allowed for any the CORS simple methods; that is,
`GET`, `POST` or `HEAD`.  These are the methods which JavaScript can already
use without CORS.  To permit additional methods, set the `cors-methods`
annotation:

```yaml
  annotations:
    ingress.kubernetes.io/enable-cors: "true"
    ingress.kubernetes.io/cors-origins: "http://example.com"
    ingress.kubernetes.io/cors-credentials: "true"
    ingress.kubernetes.io/cors-methods: "PUT, DELETE"
```

You do not need to list the simple methods in `cors-methods`, as they are always
permitted.

By default, the browser will preflight the request with a separate OPTIONS
request every time it needs to make an access control decision, which adds
a significant overhead to the request processing time.  If you expect each
client to make several CORS-authenticated requests, you can set the `cors-max-age`
annotation to the number of seconds the browser is permitted to cache the
preflight result:

```yaml
  annotations:
    ingress.kubernetes.io/enable-cors: "true"
    ingress.kubernetes.io/cors-origins: "http://example.com"
    ingress.kubernetes.io/cors-credentials: "true"
    ingress.kubernetes.io/cors-max-age: "3600"
```

By default, the browser will only permit the CORS simple headers in the
request: `Accept`, `Accept-Language`, `Content-Language`, or `Content-Type` (if
the value is `application/x-www-form-urlencoded`, `multipath/form-data` or
`text/plain`).  To allow additional request headers, set the
`ingress.kubernetes.io/cors-headers` annotation:

```yaml
  annotations:
    ingress.kubernetes.io/enable-cors: "true"
    ingress.kubernetes.io/cors-origins: "http://example.com"
    ingress.kubernetes.io/cors-credentials: "true"
    ingress.kubernetes.io/cors-headers: "X-CustomHeader"
```

## Advanced configuration

If you want to allow cross-origin requests from a specific set of domains, or
you want to control the request methods permitted or whether credentials should
be sent, do not use `enable-cors`; instead, set the
`ingress.kubernetes.io/access-control-allow-origin` annotation:

```yaml
ingress.kubernetes.io/access-control-allow-origin: "*"
```

or:

```yaml
ingress.kubernetes.io/access-control-allow-origin: "https://mydomain.com https://myothersite.com"
```

The value should be either `"*"` (meaning all origins) or a whitespace-delimited
list of origins.

You can use the following set of annotations to configure other CORS headers
in the response:

* `ingress.kubernetes.io/access-control-allow-credentials`
* `ingress.kubernetes.io/access-control-allow-methods`
* `ingress.kubernetes.io/access-control-allow-headers
* `ingress.kubernetes.io/access-control-max-age`

There is no default for these values, so you will likely want to set all of
them.

Do not set `ingress.kubernetes.io/enable-cors` at the same time as any of the
other CORS-related annotations; behaviour in that case is undefined.
