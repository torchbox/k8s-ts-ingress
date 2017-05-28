# Ingress annotations

The behaviour of an Ingress can be configured by setting annotations on the
Ingress resource, e.g.:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/rewrite-target: '/myapp'
```

Annotations whose names with `ingress.kubernetes.io` are standard annotations
supported by most Ingress controllers; those beginning with
`ingress.kubernetes.io` are specific to the Traffic Server Ingress controller.

* `ingress.kubernetes.io/rewrite-target`: if set to a string, the portion of the
  request path matched by the Ingress `path` attribute will be replaced with
  this string.  This has no effect on an Ingress without a `path` set.

* `ingress.kubernetes.io/app-root`: if set to a path, requests for `/` will be
  redirected to this path.  This can be used for applications which sit in a
  subdirectory rather than at the root.

* `ingress.kubernetes.io/follow-redirects`: if `"true"`, Traffic Server will
  follow 3xx redirect responses and serve the final response to the client.
  If the redirect destination is cached, it will be cached with the cache key
  of the original request.  Redirects will only be followed to other Ingress
  resources, not to arbitrary destinations (but see below about proxying to
  external resources).

* `ingress.kubernetes.io/preserve-host`: if `"false"`, set the `Host` header
  in the request to the backend name (e.g., the pod name), instead of the
  original request host.

* `ingress.kubernetes.io/read-response-timeout": set the time in seconds that
  TS will wait for for the response from the origin.  If this timeout is
  exceeded, an HTTP 504 error will be returned to the client.
