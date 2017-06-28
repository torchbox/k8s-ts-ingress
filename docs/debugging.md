# Debugging

To enable debug logging on an Ingress, set the `ingress.torchbox.com/debug-log`
annotation:

```yaml
metadata:
  annotations:
    ingress.torchbox.com/debug-log: "true"
```

This will log the full set of requests and responses for every transaction on
this Ingress to the Traffic Server `error.log`.  This should not be enabled
during normal operation, since it will generate a very large amount of log data,
but it can be useful to diagnose HTTP-related issues or to investigate bugs in
Traffic Server or the Ingress controller.
