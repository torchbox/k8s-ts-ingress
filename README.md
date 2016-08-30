Apache Traffic Server ingress controller for Kubernetes
=======================================================

This is a Kubernetes ingress controller using Apache Traffic Server.
Currently, it is only suitable for testing, and uses a development
version of TS 7.0.

To enable it:

    $ kubectl apply -f trafficserver.yml

It will poll for changes to ingress resources every 30 seconds.
