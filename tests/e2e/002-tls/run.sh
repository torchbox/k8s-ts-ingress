#! /bin/sh
# vim:set sw=8 ts=8 noet:

# Test basic functionality, i.e. that routing requests to an endpoint works.

set -e
output=$(curl -sS --cacert tests/test-cert.pem			\
		--resolve echoheaders.test:58443:127.0.0.1	\
		https://echoheaders.test:58443/this-is-a-test)

if echo "$output" | grep -q "Request path: /this-is-a-test"; then
	exit 0
else
	echo "Failed: output did not include test string."
	echo "Test output: [$output]"
	exit 1
fi
