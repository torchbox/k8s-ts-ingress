#! /bin/sh
# vim:set sw=8 ts=8 noet:

# Test compression.

expect_output() {
	if echo "$output" | egrep -q "$@"; then
		return 0
	else
		echo "Failed: output did not include test string: [$*]"
		echo "Test output: [$output]"
		exit 1
	fi
}

# Uncached compression.

printf '.'
output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output "^Vary: Accept-Encoding"
expect_output -v "Content-Encoding"

printf '.'
output=$(curl 2>&1 -visS --compressed -H'Accept-Encoding: gzip'	\
		--resolve echoheaders.test:58080:127.0.0.1	\
		http://echoheaders.test:58080/this-is-a-test)
expect_output "^Vary: Accept-Encoding"
expect_output "^Content-Encoding: gzip"
expect_output "^Request path: /this-is-a-test"

# Test deflate here as well.
printf '.'
output=$(curl 2>&1 -visS --compressed -H'Accept-Encoding: deflate'	\
		--resolve echoheaders.test:58080:127.0.0.1		\
		http://echoheaders.test:58080/this-is-a-test)
expect_output "^Vary: Accept-Encoding"
expect_output "^Content-Encoding: deflate"
expect_output "^Request path: /this-is-a-test"

# Cached compression.
printf '.'
output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/cached/test)
expect_output "^X-Cache-Status: hit-fresh"
expect_output "^Vary: Accept-Encoding"
expect_output -v "Content-Encoding"

printf '.'
output=$(curl 2>&1 -visS --compressed 				\
		--resolve echoheaders.test:58080:127.0.0.1 	\
		http://echoheaders.test:58080/cached/test)
expect_output "^X-Cache-Status: hit-fresh"
expect_output "^Vary: Accept-Encoding"
expect_output "^Content-Encoding"
expect_output "^Request path: /cached/test"
