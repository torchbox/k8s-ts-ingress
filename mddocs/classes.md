# Using multiple Ingress controllers

If you want to deploy more than one Ingress controller inside a cluster (for
example, to test the TS Ingress controller before deploying it properly), you
will need to use Ingress classes to control which resources should be handled
by which controller.

The Ingress class is set as an annotation on the resource:

```
metadata:
  annotations:
    kubernetes.io/ingress.class: "trafficserver"
```

The TS Ingress controller will handle any Ingress resource which does not have
an Ingress class set, or where the Ingress class is set to "trafficserver".

To change the Ingress classes that TS will handle, set `ingress_classes` in
`kubernetes.config` (or the `$TS_INGRESS_CLASSES` environment variable) to a
whitespace-separate list of values, e.g. `"trafficserver ts-staging"`.  This
can be used to run multiple copies of the TS Ingress controller in one cluster.
If you do this, the `trafficserver` class will not be handled unless you
explicitly include it in the list.

For more information, see
[Using Multiple Ingress Controller](https://github.com/nginxinc/kubernetes-ingress/tree/master/examples/multiple-ingress-controllers)
in the Kubernetes documentation.


