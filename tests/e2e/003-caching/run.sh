#! /bin/sh
# vim:set sw=8 ts=8 noet:

# Test caching.

expect_output() {
	if echo "$output" | grep -q "$@"; then
		return 0
	else
		echo "Failed: output did not include test string: [$*]"
		echo "Test output: [$output]"
		exit 1
	fi
}


set -e
output=$(curl -isS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output "X-Cache-Status: miss"

output=$(curl -isS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output "X-Cache-Status: miss"

output=$(curl -isS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/cached/test)
expect_output "X-Cache-Status: miss"

output=$(curl -isS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/cached/test)
expect_output "X-Cache-Status: hit-fresh"
