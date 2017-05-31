# Using HTTP caching

Traffic Server can cache HTTP and HTTPS responses from an application to improve
page load speed.  On a site which serves a large amount of infrequently
changing pages to anonymous users, caching can provide a significant improvement
to both performance and page load times.  It's not uncommon to see caching
improve a site's capacity from tens of requests per second to tens of thousands
of requests per second, without using any additional resources (except for
bandwidth, of course).

## Configuring caching

Caching is enabled on Ingress resources by default.  To indicate that a response
is to be cached, your application should send a `Cache-Control` header field in
the response:

```http
HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
Content-Type: text/html; charset=UTF-8
...
```

Like most HTTP header fields, this is a comma-separated list of values.  `public`
indicates that the page content does not contain private data (meaning it should
be cached by multi-user proxies like Traffic Server), and `max-age` indicates how
long it should be cached for; in this case, 3600 seconds or one hour.

As an alternative to `Cache-Control`, your application can send an `Expires`
header field containing a timestamp; the page will be cached until the expiry
time is reached.  `Expires` is not recommended for new applications, since
`Cache-Control` is more flexible and has better defined semantics.

## Disabling caching

If you want to prevent certain pages from being cached, you can indicate this
using `Cache-Control`:

```http
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
```

You should generally do this for any personalised pages, e.g. pages served to
logged-in users, or pages containing a `Set-Cookie` header field.  By default,
TS will not use the cache for requests containing a `Cookie` header field or
cache responses containing a `Set-Cookie` field, but it's better to be explicit.

To disable caching entirely on an Ingress, even if it sends `Cache-Control` or
`Expires` header fields, use the `ingress.kubernetes.io/cache-enable` annotation:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/cache-enable: "false"
```

If only some paths should have caching disabled, you can create another Ingress
resource for that particular path:

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    ingress.kubernetes.io/cache-enable: "false"
  name: echoheaders
spec:
  rules:
  - host: www.mysite.path
    http:
      paths:
      - path: /admin
        backend:
          serviceName: myapp
          servicePort: http
```

## Caching and URL parameters

When a page is cached, its URL parameters are stored in the cache to ensure that
a request with different URL parameters returns the correct content.  For
example, the URL:

```plain
http://www.mysite.com/listings/?page=1
```

will be cached differently from the URL:

```plain
http://www.mysite.com/listings/?page=2
```

Usually this is what you want and no additional configuration is required.
However, sometimes clients may request pages with additional URL parameters
which do not affect page content.  A good example of this is marketing tracking
parameters like `utm_medium` which are used by JavaScript on the page to
identify traffic sources, but do not affect the page content at all.  Because
these URL parameters do not affect page content, they should not be considered
when caching.  (The JavaScript tracking code will run anyway, so no data is
lost.)

There are two approaches to configuring this: either you can set a list of URL
parameters which should be ignored when caching (which is the safest method),
or you can set a whitelist of parameters, where any parameters not in the
list will be ignored.

To exclude a set of parameters from caching, set the
`ingress.kubernetes.io/cache-ignore-query-params` annotation on the Ingress:

```
    ingress.kubernetes.io/cache-ignore-query-params: "utm_* source_id"
```

The value should be a list of UNIX globs (`*`, `?` and `[...]` are supported);
any matching query parameters will be ignored for caching.

To set a whitelist of URL parameters, set the
`ingress.kubernetes.io/cache-whitelist-query-params` annotation:

```
    ingress.kubernetes.io/cache-whitelist-query-params: "page view include_id_*"
```

The format is the same as `cache-ignore-query-params`, but the meaning is
reversed: any URL parameter not matched will be ignored.

When using either of these annotations, you probably also want to set
`ingress.kubernetes.io/cache-sort-query-params: "true"`, which will cause the
URL parameters to be lexically sorted.  This means that a request for
`/?a=1&b=2` can be served a cached response for`/?b=2&a=1`, improving cache hit
rate across clients.

These annotations also change the query string sent to the application.  This is
to ensure the application doesn't accidentally vary the page content based on a
query parameter that has been ignored for caching.

## Caching and cookies

Usually, TS will not cache a response or serve a request from the cache if
either of the following are true:

* The request has a `Cookie` header field
* The response has a `Set-Cookie` header field

This is true even if the response includes an explicit `Cache-Control`, and is
intended to avoid accidental leakage of private data due to misconfiguration.

However, in some cases your users may have cookies set that do not affect page
content.  This is common with tracking cookies for page analytics tools; Google
Analytics, for example, sets several cookies with names like `__utma`, which are
only ever referenced from JavaScript and do not affect page content.

To allow caching to work even with these cookies set, use the
`ingress.kubernetes.io/cache-ignore-cookies` annotation:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/cache-ignore-cookies: "utm_* has_js"
```

The annotation value should be a space-delimited list of UNIX globs; any cookie
in the request `Cookie:` header field which matches one of the globs will be
removed.  If there are no cookies left, then the entire `Cookie` header field
will be removed from the request; the request can then be served from the cache,
or its response can be stored in the cache.


If any cookies remain after processing, caching will be bypassed as normal.

## Removing pages from the cache

### Removing individual URLs

You can purge individual URLs from the cache by sending an HTTP `PURGE` request
to Traffic Server.  To make this easy to do from pods, create a Service for the
TS pod.  The PURGE request should look like this:

```
PURGE http://www.mysite.com/mypage.html HTTP/1.0
```

Unfortunately, this doesn't work very well when multiple copies of TS are
running, since there's no simple way for an application to retrieve the list of
TS instances.  We plan to address this in a future release.

### Clearing the entire cache

Occasionally, you might want to clear the cache for an entire domain, for
example if some boilerplate HTML has changed that affects all pages.  To do this,
set the `ingress.kubernetes.io/cache-generation` annotation to a non-zero
integer.  This changes the cache generation for the Ingress; any objects cached
with a different generation are no longer visible, and have been effectively
removed from the cache.  Typically the cache generation would be set to the
current UNIX timestamp, although any non-zero integer will work.

## `X-Cache-Status` header

When an Ingress has caching enable, TS will include an `X-Cache-Status` header
in the HTTP response, which looks like this:

```
X-Cache-Status: hit-fresh (1496232521)
```

The number in brackets is the current cache generation configured on the Ingress.
The first word is the cache lookup status, which can be:

* `miss`: the document was not found in the cache, and TS went to the origin to
  fetch it.
* `hit-fresh`: a valid copy of the document was found in the cache, and TS
  served this copy without going to the origin.
* `hit-stale`: a stale copy of the document was found in the cache (e.g., it
  had exceeded its `max-age`), and TS went to the origin to revalidate the
  document.  The document may still have been served from the cache if the
  origin returned HTTP 304 (Not modified).
* `skipped`: TS did not do a cache lookup for the document.  This status is most
  common with internally-generated responses, such as errors and redirects.
