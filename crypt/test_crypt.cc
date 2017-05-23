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

#include	"ts_crypt.h"

using std::string;
using std::vector;
using std::equal;

namespace {
	struct crypt_test {
		string plain;
		string hashed;
	};

	vector<crypt_test> const des_tests{
		{ "test",		"fnNT2T9mSvQWw" },
		{ "test2",		"B.ugGIHw78xqQ" },
		{ "test 3", 		"w56ChDRTrnBCc" },
		/* test high bit characters */
		{ "\xff\x80\x7f\x01",	"Eg.N0HioUqx1Q" },
		/* test truncation */
		{ "averylongpassword",	"5jRKSSvq3JIWI" },
		{ "averylon",		"5jRKSSvq3JIWI" },
	};

	vector<crypt_test> const edes_tests{
		{ "test",		"_aaa.1234rKGPevsjyf2" },
		{ "test2",		"_aaa.1234xcHTzIYXJDc" },
		{ "test 3", 		"_aaa.1234PdMutmTfqxk" },
		/* test high bit characters */
		{ "\xff\x80\x7f\x01",	"_aaa.1234xGk46Gw.z/Y" },
		/* extended des does not truncate */
		{ "averylongpassword",	"_aaa.123415Rvb9PpQjc" },
		{ "averylon",		"_aaa.1234OXH3WVBhOj." },
	};

	vector<crypt_test> const md5_tests{
		{ " ", 
		  "$1$yiiZbNIH$YiCsHZjcTkYd31wkgW8JF." },

		{ "pass",
		  "$1$YeNsbWdH$wvOF8JdqsoiLix754LTW90" },

		{ "____fifteen____",
		  "$1$s9lUWACI$Kk1jtIVVdmT01p0z3b/hw1" },

		{ "____sixteen_____",
		  "$1$dL3xbVZI$kkgqhCanLdxODGq14g/tW1" },

		{ "____seventeen____",
		  "$1$NaH5na7J$j7y8Iss0hcRbu3kzoJs5V." },

		{ "__________thirty-three___________",
		  "$1$HO7Q6vzJ$yGwp2wbL5D7eOVzOmxpsy." },

		{ "Pässword",
		  "$1$NaH5na7J$MvnEHcxaKZzgBk8QdjdAQ0" },
	};

	/* bcrypt tests from Solar Designer */
	vector<crypt_test> const bcrypt_tests{
		{"\xa3",
		  "$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"},

		{ "0123456789abcdefghijklmnopqrstuvwxyz"
		  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		  "chars after 72 are ignored",
		 "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"},

		{"\xff\xff\xa3",
		 "$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"},

		{"\xff\xff\xa3",
		 "$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"},

		{"\xff\xff\xa3",
		 "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nqd1wy.pTMdcvrRWxyiGL2eMz.2a85."},

		{"\xff\xff\xa3",
		 "$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"},

		{"\xa3",
		 "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},

		{"\xa3",
		 "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},

		{"\xa3",
		 "$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},

		{"1\xa3" "345",
		 "$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi"},

		{"\xff\xa3" "345",
		 "$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi"},

		{"\xff\xa3" "34" "\xff\xff\xff\xa3" "345",
		 "$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi"},

		{"\xff\xa3" "34" "\xff\xff\xff\xa3" "345",
		 "$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi"},

		{"\xff\xa3" "34" "\xff\xff\xff\xa3" "345",
		 "$2a$05$/OK.fbVrR/bpIqNJ5ianF.ZC1JEJ8Z4gPfpe1JOr/oyPXTWl9EFd."},

		{"\xff\xa3" "345",
		 "$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e"},

		{"\xff\xa3" "345",
		 "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e"},

		{"\xa3" "ab",
		 "$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS"},

		{"\xa3" "ab",
		 "$2x$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS"},

		{"\xa3" "ab",
		 "$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS"},

		{"\xd1\x91",
		 "$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS"},

		{"\xd0\xc1\xd2\xcf\xcc\xd8",
		 "$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS"},

		{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		  "chars after 72 are ignored as usual",
		 "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6"},

		{ "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		  "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		  "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		  "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		  "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		  "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55",
		  "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy"},

		{ "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		  "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		  "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		  "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		  "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		  "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff",
		 "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe"},

		{"",
		 "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
	};

	/* Test cases from Ulrich Drepper's SHA-256 reference implementation */
	vector<crypt_test> const sha256_tests{
		{ "Hello world!",	
		  "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },

		{ "Hello world!",
		  "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZR"
		  "BAwqFMz2.opqey6IcA" },

		{ "This is just a test",
		  "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil0"
		  "7guHPvOW8mGRcvxa5" },

		{ "a very much longer text to encrypt.  This one even stretches"
		  " over morethan one line.",
		  "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIU"
		  "nzyxf12oP84Bnq1" },

		{ "we have a short salt string but not a short password",
		  "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/" },

		{ "a short string",
		  "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq"
		  "2jxPyzV/cZKmF/wJvD" },

		{ "the minimum number is still observed",
		  "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQeb"
		  "Y9l/gL972bIC" },
	};

	/* Test cases from Ulrich Drepper's SHA-512 reference implementation */
	vector<crypt_test> const sha512_tests{
		{ "Hello world!",
		  "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
		  "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1" },

		{ "Hello world!",
		  "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
		  "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." },

		{ "This is just a test",
		  "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
		  "zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0" },

		{ "a very much longer text to encrypt.  This one even stretches over more"
		  "than one line.",
		  "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
		  "vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1" },

		{ "we have a short salt string but not a short password",
		  "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
		  "ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0" },

		{ "a short string",
		  "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
		  "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1" },

		{ "the minimum number is still observed",
		  "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
		  "hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX." },
	};

	vector<crypt_test> const rfc2307_plain_tests{
		{ "plaintest",	"{PLAIN}plaintest" },
	};

	vector<crypt_test> const rfc2307_sha_tests{
		{ "shatest",	"{SHA}5tQ74+o9f/9M8qg2Ryb14BdaI7A=" },
	};

	vector<crypt_test> const rfc2307_ssha_tests{
		{ "sshatest",	"{SSHA}8eweop0v7TNF+DE00ZsXByaL8bwiPC37" },
	};

void
do_crypt_test(vector<crypt_test> const &tests,
	      crypt_fn_t crypt_fn,
	      crypt_check_fn check_fn)
{
	for (auto &&test : tests) {
	vector<char>	buf(128);
	int		n;
		
		n = crypt_fn(test.plain.c_str(), test.hashed.c_str(),
			     &buf[0], buf.size());
		ASSERT_EQ(n, 0);

		std::string hashed(&buf[0]);

		EXPECT_EQ(hashed.size(), test.hashed.size())
			<< "for [" << test.plain << "], expected ["
			<< test.hashed << "], got [" << hashed << "]";

		EXPECT_EQ(hashed, test.hashed);

		EXPECT_EQ(1, crypt_check(test.plain.c_str(), test.hashed.c_str()));
		EXPECT_EQ(1, check_fn(test.plain.c_str(), test.hashed.c_str()));
	}
}

void
do_rfc2307_test(vector<crypt_test> const &tests, crypt_check_fn fn)
{
	for (auto &&test: tests) {
		EXPECT_EQ(1, fn(test.plain.c_str(), test.hashed.c_str()));
		EXPECT_EQ(1, crypt_check(test.plain.c_str(), test.hashed.c_str()));
	}
}

} // anonymous namespace

TEST(Crypt, DES) {
	do_crypt_test(des_tests, crypt_des, crypt_check_des);
}

TEST(Crypt, ExtendedDES) {
	do_crypt_test(edes_tests, crypt_des, crypt_check_des);
}

TEST(Crypt, MD5) {
	do_crypt_test(md5_tests, crypt_md5, crypt_check_phk_md5);
}

TEST(Crypt, Bcrypt) {
	do_crypt_test(bcrypt_tests, crypt_blowfish, crypt_check_blowfish);
}

TEST(Crypt, SHA256) {
	do_crypt_test(sha256_tests, crypt_sha256, crypt_check_sha256);
}

TEST(Crypt, SHA512) {
	do_crypt_test(sha512_tests, crypt_sha512, crypt_check_sha512);
}

TEST(Crypt, RFC2307Plain) {
	do_rfc2307_test(rfc2307_plain_tests, crypt_check_rfc2307_plain);
}

TEST(Crypt, RFC2307SHA) {
	do_rfc2307_test(rfc2307_sha_tests, crypt_check_rfc2307_sha);
}

TEST(Crypt, RFC2307SSHA) {
	do_rfc2307_test(rfc2307_ssha_tests, crypt_check_rfc2307_ssha);
}
