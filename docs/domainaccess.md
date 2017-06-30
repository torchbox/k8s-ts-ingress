# Domain access control

Domain access control allows the server administrator to control which domains
each namespace is allowed to use.  This lets you operate multi-tenant clusters
without one namespace being able to (accidentally or maliciously) intercept
traffic intended for a different namespace.

To configure domain access control, set the option `domain-access-list` in the
[TS ConfigMap](config.md):

```
domain-access-list: *fooapp.com:fooapp-prod,fooapp-staging baz.bar.com:baz-microsite
```

The format is list of `<domain>:<namespace>[,<namespace>...]` entries separated
by whitespace.  The list is matched in order; the first matching entry for a
particular Ingress's hostname is used to determine access.  If the namespace
containing the Ingress does not appear after the ':' for that entry, the Ingress
will be ignored.

Domains can be listed in several ways:

* `*` will match any domain;
* `www.myapp.com` will match only `www.myapp.com`, not `myapp.com`;
* `*.myapp.com` will match `sub.myapp.com` but not `other.sub.myapp.com` or
  `myapp.com`.
* `*myapp.com` will match `myapp.com` and `sub.myapp.com`, but not
  `other.sub.myapp.com`.

Generally, to delegate an entire domain (such as `myapp.com`) to a namespace,
you will want to use the `*myapp.com` form.

The special namespace `*` will match any namespace.  To permit domains not
explicitly listed to be used by any namespace, add `*:*` to the end of the list.
(By default, any domain not explicitly listed is denied.)
