#! /bin/sh
# vim:set sw=8 ts=8 noet:

# Test basic functionality, i.e. that routing requests to an endpoint works.

set -e

expect_output() {
	if echo "$output" | egrep -q "$@"; then
		return 0
	else
		echo "Failed: output did not include test string: [$*]"
		echo "Test output: [$output]"
		exit 1
	fi
}


set -e


# If there's no Origin header in the request, the response should not include
# any CORS headers.
printf '.'
output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'
expect_output -v 'Access-Control-'

printf '.'
output=$(curl 2>&1 -XOPTIONS -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'
expect_output -v 'Access-Control-'

# Simple requests should include Access-Control-Allow-Origin, but no other
# headers.
printf '.'
output=$(curl 2>&1 -visS -H'Origin: http://example.com'		\
		--resolve echoheaders.test:58080:127.0.0.1	\
		http://echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'
expect_output 'Access-Control-Allow-Origin: \*'
expect_output -v 'Access-Control-Allow-Methods'
expect_output -v 'Access-Control-Allow-Headers'
expect_output -v 'Access-Control-Allow-Credentials'
expect_output -v 'Access-Control-Max-Age'

# Preflight requests for a public resource should include allow-origin and
# max-age, but not any other headers, because we only want to allow simple
# requests.
printf '.'
output=$(curl 2>&1 -visS -XOPTIONS					\
		-H'Origin: http://example.com'				\
		-H'Access-Control-Request-Method: POST'			\
		--resolve echoheaders.test:58080:127.0.0.1		\
		http://echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 204 No content'
expect_output 'Access-Control-Allow-Origin: \*'
expect_output 'Access-Control-Max-Age: 3600'
expect_output -v 'Access-Control-Allow-Methods'
expect_output -v 'Access-Control-Allow-Headers'
expect_output -v 'Access-Control-Allow-Credentials'

# Preflight request for a private resource.
printf '.'
output=$(curl 2>&1 -visS -XOPTIONS					\
		-H'Origin: http://example.com'				\
		-H'Access-Control-Request-Method: POST'			\
		--resolve private.echoheaders.test:58080:127.0.0.1	\
		http://private.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 204 No content'
expect_output 'Access-Control-Allow-Origin: http://example.com'
expect_output -v 'Access-Control-Max-Age'
expect_output 'Access-Control-Allow-Methods: PUT, DELETE'
expect_output 'Access-Control-Allow-Headers: X-CustomHeader'
expect_output 'Access-Control-Allow-Credentials: true'

# Preflight request for a private resource with an incorrect origin.
printf '.'
output=$(curl 2>&1 -visS -XOPTIONS					\
		-H'Origin: http://wrong.example.com'			\
		-H'Access-Control-Request-Method: POST'			\
		--resolve private.echoheaders.test:58080:127.0.0.1	\
		http://private.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'
expect_output -v 'Access-Control-Allow-Origin'
expect_output -v 'Access-Control-Max-Age'
expect_output -v 'Access-Control-Allow-Methods'
expect_output -v 'Access-Control-Allow-Headers'
expect_output -v 'Access-Control-Allow-Credentials'
