# HTTP compression

HTTP compression allows the response body of an HTTP transation to be compressed
to reduce its size, saving bandwidth and decreasing page load times.  Both the
gzip and Brotli algorithms are supported; gzip is the most common and
widely-supported algorithm, while Brotli is a newer algorithm specifically
designed to perform well for typical HTTP content (like HTML).

SDCH (an experimental delta-compression algorithm) and deflate (an uncommon
gzip-like format) are not supported.

HTTP compression is enabled by default.  To disable compression on an Ingress,
set the `ingress.kubernetes.io/compress-enable` annotation to `"false"`:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/compress-enable: "false"
```

HTTP compression is only used for certain file types.  It doesn't make sense to
compress images, for example, since common image file formats already include
compression, and a second layer of compression would only waste CPU cycles
without any reduction in file size.

By default, the following content types are compressed:

* `text/css`
* `text/x-component`
* `text/plain`
* `font/opentype`
* `image/svg+xml`
* `image/x-icon`
* `application/atom+xml`
* `application/rss+xml`
* `application/javascript`
* `aplication/x-javascript`
* `application/json`
* `application/vnd.ms-fontobject`
* `application/x-font-ttf`
* `application/x-web-app-manifest+json`

This is a reasonable default list for most sites, but if you want to provide
your own list, set the `ingress.kubernetes.io/compress-types` annotation:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/compress-types: "test/css application/javascript application/vnd.my-special-type"
```

## HTTP compression and caching

TS always fetches uncompressed documents from the origin server (the application),
and stores uncompressed pages in its cache.  If the client requests a
compressed response, the document is compressed on the fly while sending it to
the client.

This avoids a common problem with caching based on the value of the
`Accept-Encoding` header (e.g. using `Vary`): if a compressed version of the
document is cached, and the client requests an uncompressed version, TS will go
to the origin to fetch the new version.  If the page has changed and not been
purged in the mean time, this can lead to different version of the document
being returned depending on whether the client supports compression, leading
to strange and difficult to debug problems.

The disadvantage of this method is that it increases TS CPU usage; this may
become an issue if you are serving a lot of traffic (several hundred Mbits/sec
or more).  If this is an issue for you, you can disable compression on the
Ingress, and return compressed responses from your application instead, using
`Vary: Accept-Encoding`.

We may implement a more efficient compression mechanism (likely a hybrid of
these two options) in a future release.

## HTTP compression and TLS BREACH

Document types that commonly contain sensitive content (such as `text/html`)
are not included on the default compression list.  This is because compressing
those content types can leave applications open to the TLS
[BREACH](https://en.wikipedia.org/wiki/BREACH) attack, allowing plaintext page
content (such as CSRF tokens) to be recovered from encrypted data.

If you add these content types to the `compress-types` list, especially
`text/html`, you must ensure your application is not affected; for example if
your application:

* does not include sensitive data in the page body;
* does not use TLS and is therefore insecure anyway;
* includes sensitive data in the page body, but does so in a way specifically
  designed to resist attack via BREACH (for example, Django version 1.10 or
  newer).

If you are not certain that your application meets at least one of these
requirements, you should not enable compression of HTML.

There are methods to mitigate BREACH in the proxy layer, for example "length
hiding", which obfuscates the length of the returned document by appending
random comment data to the HTML.  We may implement this in a future version if
there is any user demand for it.
