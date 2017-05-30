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

## Basic CORS configuration

To enable cross-origin requests from any domain, set the
`ingress.kubernetes.io/enable-cors` annotation on the Ingress resource:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/enable-cors: "true"
```

This will allow requests from any origin, with credentials, with the following
request methods: `GET`, `PUT`, `POST`, and `DELETE`.

This must **only** be used for Ingress resources that serve static assets, or
dynamic pages that do not use any sort of authentication (including cookies);
otherwise, any page on the Internet will be able to steal users' credentials.

Setting `enable-cors: "true"` is equivalent to setting the following annotations:

```
ingress.kubernetes.io/access-control-allow-origin: "*"
ingress.kubernetes.io/access-control-allow-credentials: "true"
ingress.kubernetes.io/access-control-allow-methods: "GET, PUT, POST, DELETE, OPTIONS"
ingress.kubernetes.io/access-control-allow-headers: "DNT, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Authorization"
ingress.kubernetes.io/access-control-max-age: "1728000"
```

Note that the nginx Ingress controller adds "`X-CustomHeader`" to the CORS
header list if `enable-cors` is set.  We believe this is a mistake, and the TS
implementation will not add that header.

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

The value should be either `"*"` (meaning all origins), or a whitespace-delimited
list of origins.


