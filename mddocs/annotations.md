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
`ingress.torchbox.com` are specific to the Traffic Server Ingress controller.

* `ingress.kubernetes.io/rewrite-target`: if set to a string, the portion of the
  request path matched by the Ingress `path` attribute will be replaced with
  this string.  This has no effect on an Ingress without a `path` set.

* `ingress.kubernetes.io/app-root`: if set to a path prefix, and the request URI
  does not begin with that prefix, then a redirect will be returned to this
  path.  This can be used for applications which sit in a subdirectory rather
  than at the root.

* `ingress.torchbox.com/follow-redirects`: if `"true"`, Traffic Server will
  follow 3xx redirect responses and serve the final response to the client.
  If the redirect destination is cached, it will be cached with the cache key
  of the original request.  Redirects will only be followed to other Ingress
  resources, not to arbitrary destinations (but see below about proxying to
  external resources).

* `ingress.torchbox.com/preserve-host`: if `"false"`, set the `Host` header
  in the request to the backend name (e.g., the pod name), instead of the
  original request host.


