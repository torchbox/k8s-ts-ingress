# Proxying to external services

Sometimes, you might want to proxy traffic to a service that doesn't run as a
Kubernetes pod.  This can be used to expose external services via an Ingress,
and to allow the `follow-redirects` annotation to access external resources.

## External proxying via IP address

To proxy requests to a particular IP address or a set of IP address, create a
`Service` resource without a selector, and create its associated `Endpoints`
resource:

```yaml
kind: Service
apiVersion: v1
metadata:
  name: external-service
spec:
  ports:
  - protocol: TCP
    port: 80

---

kind: Endpoints
apiVersion: v1
metadata:
  name: external-service
subsets:
- addresses:
  - ip: 1.2.3.4
  ports:
  - port: 80
```

You can now define an Ingress to route traffic to this service:

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: external-ingress
spec:
  rules:
  - host: external.example.com
    http:
      paths:
      - backend:
          serviceName: external-service
          servicePort: 80
```

Traffic Server will now route requests for `http://external.example.com/` to your
external service at IP address `1.2.3.4`.

## External proxying via hostname

To proxy to an external hostname, create a `Service` resource of type
`ExternalName`:

```yaml
kind: Service
apiVersion: v1
metadata:
  name: external-service
spec:
  type: ExternalName
  externalName: my-external-backend.example.com
```

You do not need to configure an `Endpoints` resource as with an external IP
address.  Create an Ingress for this Service:

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: external-ingress
  annotations:
    ingress.kubernetes.io/preserve-host: "false"
spec:
  rules:
  - host: external.example.com
    http:
      paths:
      - backend:
          serviceName: external-service
          servicePort: 80
```

Now requests for `http://external.example.com` will be proxied to
`http://my-external-backend.example.com`.

When using an ExternalName Service, the `servicePort` must be an integer;
named ports are not supported.

In most cases, you will want to set the `preserve-host` annotation to `"false"`
so that the external service sees the hostname it's expecting, rather than the
hostname in the client request.

## External proxying and TLS

By default, even if a request uses TLS, it will be proxied to the external
backend via HTTP.  To use TLS for the backend, set an annotation on the Ingress:
`ingress.kubernetes.io/secure-backends: "true"`.  This is not very useful for
external IP addresses, because it's unlikely the backend will have a TLS
certificate for its IP address, but it will work well with `ExternalName`
services.

For TLS to work, remember to set `servicePort` to `443` (or some other suitable
value).


