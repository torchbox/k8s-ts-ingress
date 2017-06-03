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

printf '.'

# Test password-only authentication with all supported crypt algorithms.

output=$(curl 2>&1 -visS --resolve echoheaders.test:58080:127.0.0.1 \
		http://echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 401 Unauthorized'
expect_output 'WWW-Authenticate: Basic realm="auth test"'

for credentials in	\
		plaintest:plaintest	\
		destest:destest		\
		md5test:md5test		\
		bftest:bfest		\
		sha256test:sha256test	\
		sha512test:sha512test	\
		shatest:shatest		\
		sshatest:sshatest; do
	printf '.'
	output=$(curl 2>&1 -vsS -u plaintest:plaintest			\
			--resolve echoheaders.test:58080:127.0.0.1	\
			http://echoheaders.test:58080/this-is-a-test)
	expect_output 'HTTP/[012.]* 200 OK'
done

#	SATISFY		IP CORRECT?	AUTH CORRECT?
#
#	ALL		YES		YES
printf '.'
output=$(curl 2>&1 -visS -u plaintest:plaintest				\
		--resolve all-ipok.echoheaders.test:58080:127.0.0.1	\
		http://all-ipok.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'

#	ALL		YES		NO
printf '.'
output=$(curl 2>&1 -visS -u plaintest:laintest				\
		--resolve all-ipok.echoheaders.test:58080:127.0.0.1	\
		http://all-ipok.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 401 Unauthorized'
expect_output 'WWW-Authenticate: Basic realm="auth test"'

#	APP		NO		YES
printf '.'
output=$(curl 2>&1 -visS -u plaintest:plaintest				\
		--resolve all-ipbad.echoheaders.test:58080:127.0.0.1	\
		http://all-ipbad.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 403 Forbidden'

#	ALL		NO		NO
printf '.'
output=$(curl 2>&1 -visS -u plaintest:laintest				\
		--resolve all-ipbad.echoheaders.test:58080:127.0.0.1	\
		http://all-ipbad.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 403 Forbidden'

#	ANY		YES		YES
printf '.'
output=$(curl 2>&1 -visS -u plaintest:plaintest				\
		--resolve any-ipok.echoheaders.test:58080:127.0.0.1	\
		http://any-ipok.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'

#	ANY		YES		NO
printf '.'
output=$(curl 2>&1 -visS -u plaintest:laintest				\
		--resolve any-ipok.echoheaders.test:58080:127.0.0.1	\
		http://any-ipok.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'

#	ANY		NO		YES
printf '.'
output=$(curl 2>&1 -visS -u plaintest:plaintest				\
		--resolve any-ipbad.echoheaders.test:58080:127.0.0.1	\
		http://any-ipbad.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 200 OK'

#	ANY		NO		NO
printf '.'
output=$(curl 2>&1 -visS -u plaintest:laintest				\
		--resolve any-ipbad.echoheaders.test:58080:127.0.0.1	\
		http://any-ipbad.echoheaders.test:58080/this-is-a-test)
expect_output 'HTTP/[012.]* 401 Unauthorized'
expect_output 'WWW-Authenticate: Basic realm="auth test"'
