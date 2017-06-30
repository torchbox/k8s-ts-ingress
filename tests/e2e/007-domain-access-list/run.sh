#! /bin/sh
# vim:set sw=8 ts=8 noet:

expect_output() {
	if echo "$output" | egrep -q "$@"; then
		return 0
	else
		echo "Failed: output did not include test string: [$*]"
		echo "Test output: [$output]"
		exit 1
	fi
}

# This request should be allowed.
printf '.'
output=$(curl 2>&1 -vsS --resolve echoheaders.test:58080:127.0.0.1	\
		http://echoheaders.test:58080/this-is-a-test)
expect_output "Request path: /this-is-a-test"
expect_output 'HTTP/[012.]* 200'

# And this one
printf '.'
output=$(curl 2>&1 -vsS --resolve www.echoheaders.test:58080:127.0.0.1	\
		http://www.echoheaders.test:58080/this-is-a-test)
expect_output "Request path: /this-is-a-test"
expect_output 'HTTP/[012.]* 200'

# But not this one
printf '.'
output=$(curl 2>&1 -vsS --resolve notechoheaders.test:58080:127.0.0.1	\
		http://notechoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 404'
