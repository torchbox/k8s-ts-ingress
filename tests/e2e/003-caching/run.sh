#! /bin/sh
# vim:set sw=8 ts=8 noet:

# Test caching.

expect_output() {
	if echo "$output" | egrep -iq "$@"; then
		return 0
	else
		echo "Failed: output did not include test string: [$*]"
		echo "Test output: [$output]"
		exit 1
	fi
}


set -e

# Test non-TLS caching.
printf '.'
output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/cached/test)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/cached/test)
expect_output "X-Cache-Status: hit-fresh"

# TLS requests for the same resource should be cached differently.
printf '.'
output=$(curl 2>&1 -visS --cacert tests/test-cert.pem		\
		--resolve echoheaders.test:58443:127.0.0.1	\
		https://echoheaders.test:58443/cached/test)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --cacert tests/test-cert.pem		\
		--resolve echoheaders.test:58443:127.0.0.1	\
		https://echoheaders.test:58443/cached/test)
expect_output "X-Cache-Status: hit-fresh"

# Test X-Next-Hop-Cache-Control
printf '.'
output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/cached/nexthopcc/test)
expect_output "Cache-Control: no-cache, max-age=3600, public"
expect_output -iv "X-Next-Hop-Cache-Control"

# Requests with cookies should not be cached.
printf '.'
output=$(curl 2>&1 -visS -H'Cookie: __utma=1234'		\
		--resolve echoheaders.test:58080:127.0.0.1	\
		http://echoheaders.test:58080/cached/test)
expect_output "X-Cache-Status: skipped"

# Responses with cookies should not be cached, even with cache-control headers.
printf '.'
output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1	\
		http://echoheaders.test:58080/cached/setcookie/test)
expect_output "X-Cache-Status: miss"
output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1	\
		http://echoheaders.test:58080/cached/setcookie/test)
expect_output "X-Cache-Status: miss"

# Ignored URL params should not affect caching, but non-ignored params should.
printf '.'
output=$(curl 2>&1 -visS --resolve ignore.echoheaders.test:58080:127.0.0.1 \
		http://ignore.echoheaders.test:58080/cached/url1)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --resolve ignore.echoheaders.test:58080:127.0.0.1 \
		http://ignore.echoheaders.test:58080/cached/url1)
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS --resolve ignore.echoheaders.test:58080:127.0.0.1 \
		'http://ignore.echoheaders.test:58080/cached/url1?badparam1=x')
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS --resolve ignore.echoheaders.test:58080:127.0.0.1 \
		'http://ignore.echoheaders.test:58080/cached/url1?goodparam1=x')
expect_output "X-Cache-Status: miss"

# Whitelisted URL params should affect caching, but non-whitelisted params
# should not.
printf '.'
output=$(curl 2>&1 -visS --resolve whitelist.echoheaders.test:58080:127.0.0.1 \
		http://whitelist.echoheaders.test:58080/cached/url2)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --resolve whitelist.echoheaders.test:58080:127.0.0.1 \
		http://whitelist.echoheaders.test:58080/cached/url2)
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS --resolve whitelist.echoheaders.test:58080:127.0.0.1 \
		'http://whitelist.echoheaders.test:58080/cached/url2?badparam1=x')
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS --resolve whitelist.echoheaders.test:58080:127.0.0.1 \
		'http://whitelist.echoheaders.test:58080/cached/url2?goodparam1=x')
expect_output "X-Cache-Status: miss"

# Ignored cookies should not affect caching, but non-ignored cookies should.
printf '.'
output=$(curl 2>&1 -visS --resolve ignore.echoheaders.test:58080:127.0.0.1 \
		http://ignore.echoheaders.test:58080/cached/url3)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --resolve ignore.echoheaders.test:58080:127.0.0.1 \
		http://ignore.echoheaders.test:58080/cached/url3)
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS -H'Cookie: badcookie1=x'			\
		--resolve ignore.echoheaders.test:58080:127.0.0.1	\
		'http://ignore.echoheaders.test:58080/cached/url3')
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS -H'Cookie: goodcookie1=x'			\
		--resolve ignore.echoheaders.test:58080:127.0.0.1	\
		'http://ignore.echoheaders.test:58080/cached/url3')
expect_output "X-Cache-Status: skipped"

# Whitelisted cookies should affect caching, but non-whitelisted cookies
# should not.
printf '.'
output=$(curl 2>&1 -visS --resolve whitelist.echoheaders.test:58080:127.0.0.1 \
		http://whitelist.echoheaders.test:58080/cached/url4)
expect_output "X-Cache-Status: miss"

output=$(curl 2>&1 -visS --resolve whitelist.echoheaders.test:58080:127.0.0.1 \
		http://whitelist.echoheaders.test:58080/cached/url4)
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS -H'Cookie: badcookie1=x'			\
		--resolve whitelist.echoheaders.test:58080:127.0.0.1	\
		'http://whitelist.echoheaders.test:58080/cached/url4')
expect_output "X-Cache-Status: hit-fresh"

output=$(curl 2>&1 -visS -H'Cookie: goodcookie1=x'			\
		--resolve whitelist.echoheaders.test:58080:127.0.0.1	\
		'http://whitelist.echoheaders.test:58080/cached/url4')
expect_output "X-Cache-Status: skipped"
