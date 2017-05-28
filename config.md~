# Configuration

There are two ways to configure the controller: you can pass a configuration
file to the plugin in `plugin.config`, or you can set the configuration in the
environment.  If a configuration option is set in both the configuration file
and the environment, the value from the environment takes precedence.

To load a configuration file, pass its name as an argument to the plugin in
`plugin.config`:

```
kubernetes.so /path/to/kubernetes.config
```

If the configuration filename is a relative pathname, it will be loaded from
TS's configuration directory (the place where `records.config` is located).

If you're deploying from the Docker image, using environment variables is the
recommended method; you would have to rebuild the Docker image to add a
configuration file.

## Kubernetes API server configuration

If TS is running inside the cluster, you do not need to configure the API
server connection details; they will be picked up automatically from the pod's
service account.  However, if you are running outside the cluster you need to
specify the API server URL and any credentials required to authenticate to it.

* `server: <url>`: set the URL (http or https) of the API server the controller
  should connect to.  (`$TS_SERVER`)

* `cafile: <filename>`: the filename of a PEM-encoded certificate file or
  bundle that will be used to validate a TLS connection to the API server.
  Ignored if the connection to the API server does not use TLS.  (`$TS_CAFILE`)

* `verify_tls: <true|false>`: whether to verify the API server's TLS certificate.
  There should be no need to disable this.  (`$TS_VERIFY_TLS`)

* `certfile: <filename>`: the filename of a PEM-encoded TLS certificate that
  will be used to authenticate to the API server.  If set, you must supply a TLS
  key as well. (`$TS_CERTFILE`)

* `keyfile: <filename>`: the filename of a PEM-encoded TLS key that will be used
  to authenticate to the API server.  If set, you must supply a TLS certificate
  as well.  (`$TS_KEYFILE`)

* `token: <token>`: an authentication Bearer token that will be used to
  authenticate to the API server, if using token authentication.  (`$TS_TOKEN`)

## Global configuration

* `ingress_classes: <class> [<class> ...]`: a list of Ingress classes that the
  controller will process.  See [Using multiple Ingress classes](classes.md) for
  more information on this option. Default: `trafficserver`.
  (`$TS_INGRESS_CLASSES`)

* `tls: <true|false>`: whether to handle TLS certificates.  If set to `false`,
  you will need to load TLS certificates by some other mechanism.  Default:
  `true`.  (`$TS_TLS`)

* `remap: <true|false>`: whether to handle host and path remapping.  If set to
  `false`, only TLS certificate loading will be done.  Default: `true`.
  (`$TS_REMAP`)

* `x_forwarded_proto: <true|false>`: whether to send an `X-Forwarded-Proto`
  header to backends, containing the client protocol (`http` or `https`).
  Default: `true`.  (`$TS_X_FORWARDED_PROTO`)
