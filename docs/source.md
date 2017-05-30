# Installing the plugin from source

If you want to integrate Kubernetes with an existing Traffic Server installation,
you can build the plugin from source.  If you're planning to deploy the plugin
inside a Kubernetes cluster, you should read [Using the Docker image](docker.md)
instead.

## Requirements

The following are required to build:

* Traffic Server 7.1 or later (including development headers).  Older versions
  might work, but are not tested or supported.  In particular, TS 7.0 (the
  latest released version) is currently not supported; we intend to address this
  in a future release of the plugin.
* A working C99 compiler and `make` utility.
* json-c library
* cURL library
* OpenSSL (or a compatible TLS library, e.g. LibreSSL)

If you want to run the unit tests, a C++11 compiler is required.  If you want to
run the end-to-end tests, a Linux/amd64 host is required (because those tests
require running the Kubernetes API server).

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

To run the unit tests:

```sh
$ make test
```

To run the end-to-end tests:

```sh
$ tests/e2erun.sh
```

## Configuration


If Traffic Server is not running inside the cluster, you will need to provide a
`kubernetes.config` configuration file.  See [Configuration](config.md) for
details.

If TS is running inside the cluster, it will pick up its service account details
automatically and the configuration file is not required, but you will need to
ensure it has access to the resources it needs to run.  If you're using RBAC
for authorization, see `rbac.yaml` for an example RBAC configuration.
