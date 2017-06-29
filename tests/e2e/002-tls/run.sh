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

expect_output() {
	if echo "$output" | egrep -q "$@"; then
		return 0
	else
		echo "Failed: output did not include test string: [$*]"
		echo "Test output: [$output]"
		exit 1
	fi
}

# Test minimum TLS 1.0.
printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.0 --resolve tls10.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'HTTP/[012.]* 200 OK'

printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.1 --resolve tls10.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'HTTP/[012.]* 200 OK'

printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.2 --resolve tls10.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'HTTP/[012.]* 200 OK'

# Test minimum TLS 1.1.
printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.0 --resolve tls11.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'sslv3 alert handshake failure'

printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.1 --resolve tls11.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'HTTP/[012.]* 200 OK'

printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.2 --resolve tls11.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'HTTP/[012.]* 200 OK'

# Test minimum TLS 1.2.
printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.0 --resolve tls12.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'sslv3 alert handshake failure'

printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.1 --resolve tls12.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'sslv3 alert handshake failure'

printf '.'
output=$(curl 2>&1 -kvisS --tlsv1.2 --resolve tls12.echoheaders.test:58443:127.0.0.1 \
		https://echoheaders.test:58443/)
expect_output 'HTTP/[012.]* 200 OK'
