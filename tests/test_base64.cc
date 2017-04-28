/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

/*
 * Tests for base64.c: base64 encoding/decoding functions.
 */

#include	<vector>
#include	<cstring>

#include	"gtest/gtest.h"

#include	"base64.h"

using std::string;
using std::vector;
using std::equal;

namespace {
	struct base64_test {
		string plain;
		string encoded;
	};

	vector<base64_test> const tests{
		{ "test",		"dGVzdA==" },
		{ "test2",		"dGVzdDI=" },
		{ "test 3",		"dGVzdCAz" },
		{ string("\xff\x80\x7f\x00", 4),
					"/4B/AA==" },
	};
}

TEST(Base64, Encode) 
{
	for (auto &&test : tests) {
	size_t	n = base64_encode_len(test.plain.size());
		ASSERT_EQ(n, test.encoded.size());

		vector<char> encoded(n);
		base64_encode((unsigned char const *)test.plain.data(),
			      test.plain.size(),
			      &encoded[0]);

		ASSERT_TRUE(equal(test.encoded.begin(), test.encoded.end(),
				  encoded.begin()))
			<< "expected [" << test.encoded << "], got ["
			<< string(encoded.begin(), encoded.end()) << "]";
	}
}

TEST(Base64, Decode)
{
	for (auto &&test : tests) {
	ssize_t	n = base64_decode_len(test.encoded.size());
		ASSERT_GE(n, 0);
		ASSERT_GE((size_t) n, test.plain.size());

		vector<char> decoded(n);
		n = base64_decode(test.encoded.data(),
				  test.encoded.size(),
				  (unsigned char *)&decoded[0]);

		ASSERT_GE(n, 0);
		ASSERT_EQ((size_t) n, test.plain.size());
		decoded.resize(n);

		ASSERT_TRUE(equal(test.plain.begin(), test.plain.end(),
				  decoded.begin()))
			<< "expected [" << test.plain << "], got ["
			<< string(decoded.begin(), decoded.end()) << "]";
	}
}
