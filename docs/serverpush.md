# HTTP/2 Server Push

HTTP/2 server push is a mechanism to allow a server to return multiple documents
in response to a single HTTP request.  Server push can be used to improve page
load performance when the server knows that a client requesting one document
will also request another document; for example, when the client requests an HTML
page, the server might also include the page's assets in its response.  This
avoids the need for the client to download and parse the HTML before requesting
the assets, reducing the total number of HTTP transactions and improving the
page load time.

However, server push has the significant disadvantage that the pushed documents
are _always_ sent to the client, even if the client already has them in its
cache and wouldn't have requested them otherwise.  Thus, pushing every asset
used on a page can easily reduce performance (and waste bandwidth) by forcing
the client to download objects it already has.  We may look at ways of mitigating
this on the server side in a future release (by detecting which assets the client
might already have), but there is currently no perfect solution to this problem.

Deciding when to use server push is a complicated and application-specific issue,
which we won't cover here.  The following article may be helpful:

* [Smashing Magazine: "A Comprehensive Guide To HTTP/2 Server Push"](https://www.smashingmagazine.com/2017/04/guide-http2-server-push/)

## Configuring Server Push

Server push is enabled by default.  If you want to disable server push on an
Ingress, use the `ingress.kubernetes.io/server-push` annotation:

```yaml
metadata:
  annotations:
    ingress.kubernetes.io/server-push: "false"
```

Like other implementations, Traffic Server uses the `Link` header field in the
HTTP response to determine what content to push to the client.  Processing is
done as soon as the response header is received, so if your application is slow
to generate the response body, it can still begin pushing assets to the client
once the header is sent.

To push a document, include a `Link` header field in your response with the
`rel=preload` attribute:

```http
Link: </path/to/my.css>; rel=preload; as=style
```

The argument to the `as` attribute should be one of the standard request
destinations ("audio", "document", "embed", "font", "image", "manifest", "object",
"report", "script", "serviceworker", "sharedworker", "style", "track", "video",
"worker", or "xslt") although TS does not enforce this and will push the object
anyway.

If you want to include a `rel=preload` link but not use server push for that
resource, add the `nopush` attribute:

```http
Link: </path/to/my/image.jpeg>; rel=preload; as=image; nopush
```

## Server Push and caching

Before TS can push an object to the client, it must have a copy of the object
itself.  This means you should almost always enable [caching](caching.md) on
assets you intend to push; otherwise, the client will have to wait while TS
goes back to the application to fetch each pushed asset, and you have lost a
significant fraction of the performance you might gain from using server push.
