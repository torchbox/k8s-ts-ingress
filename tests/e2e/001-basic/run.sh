#! /bin/sh
# vim:set sw=8 ts=8 noet:

# Test basic functionality, i.e. that routing requests to an endpoint works.

set -e
output=$(curl -sS --resolve echoheaders.test:58080:127.0.0.1 http://echoheaders.test:58080/this-is-a-test)

if echo "$output" | grep -q "Request path: /this-is-a-test"; then
	exit 0
else
	echo "Failed: output did not include test string."
	exit 1
fi
