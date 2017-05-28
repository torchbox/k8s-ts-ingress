# Using the Docker image on Kubernetes

We provide two examples Kubernetes deployments for the TS ingress controller:

* `example-daemonset.yaml` uses a DaemonSet, with an example of using node
  taints and affinity to run the controller only on master nodes, and exposes
  TS using a hostPort;
* `example-deployment.yaml` uses a Deployment, with a nodePort Service used to
  expose TS.
 
You will probably want to read and edit one of these files before using it.

Unfortunately, there are many different ways to expose an Ingress controller on
Kubernetes, and we can't document every possible variation, so you will need to
decide what method is best for your cluster.

## Runtime configuration

Most Traffic Server configuration (`records.config` entries) can be changed
using environment variables; see the
[Traffic Server Documentation](https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.config.en.html#environment-overrides).  For example, to make Traffic Server listen on port 7080 for HTTP requests,
set `PROXY_CONFIG_HTTP_SERVER_PORTS=7080`.

The TS Docker image provides one additional environment variable:

* `TS_CACHE_SIZE=nnn`: Size of the on-disk cache file to create, in megabytes.

## Cache storage

The example deployment resources use an `emptyDir` for cache storage.  This
means the cache will persist across node reboots, but will we cleared if the
pod is move to a different node, or if it's upgraded (which deletes the old pod).

The cache file will be created automatically on startup if it doesn't exist.

For persistent cache storage, mount a volume on `/var/lib/trafficserver`. 
However, be aware that only one instance of TS can access the cache at once.  If
you are running multiple copies, you will need to create a separate PV for each
instance (perhaps by using a StatefulSet instead of a DaemonSet).

