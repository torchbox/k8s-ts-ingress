# Installing the plugin from source

If you want to integrate Kubernetes with an existing Traffic Server installation,
you can build the plugin from source.  If you're planning to deploy the plugin
inside a Kubernetes cluster, you should read [Using the Docker image](docker.md)
instead.

## Requirements

The following are required to build:

* Traffic Server 7.0 or later (including development headers).  Older versions
  might work, but are not tested or supported.
* A working C99 compiler and `make` utility.
* json-c library
* cURL library
* OpenSSL (or a compatible TLS library, e.g. LibreSSL)

## Building

To build and install the plugin:

```sh
$ autoreconf -if            # only if building from a git checkout
$ ./configure [--with-tsxs=/path/to/trafficserver/bin/tsxs]
$ make
$ make install
```

This will put `kubernetes.so` in your Traffic Server plugins directory.  Edit
`plugin.config` to tell Traffic Server to load the plugin.

## Configuration


If Traffic Server is not running inside the cluster, you will need to provide a
configuration file.  Copy `kubernetes.config.example` to the Traffic Server
configuration directory, rename it to `kubernetes.config`, and edit it as
appropriate.

You will need to tell the plugin to load the configuration file in `plugin.config`:

```
kubernetes.so kubernetes.conf
```

If TS is running inside the cluster, it will pick up its service account details
automatically and the configuration file is not required, but you will need to
ensure it has access to the resources it needs to run.  If you're using RBAC
for authorization, see `rbac.yaml` for an example RBAC configuration.
