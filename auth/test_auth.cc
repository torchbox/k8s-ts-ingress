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
 * Tests for auth.c: authentication primitives.
 */

#include	<string>
#include	<vector>
#include	<map>
#include	<cstring>

#include	"auth.h"
#include	"remap.h"

#include	"gtest/gtest.h"

using std::vector;
using std::map;
using std::string;

namespace {
	struct address_test {
		string	ip;
		string	network;
		int	prefix_length;
		int	expect;
	};

	vector<address_test> const ipv4_address_tests{
		/* ip		network		pfxlen	expect */
		{ "127.0.0.1",	"127.0.0.0",	8,	1	},
		{ "127.0.0.1",	"127.0.0.0",	32,	0	},
		{ "127.0.0.1",	"127.0.0.1",	32,	1	},
		{ "127.0.0.1",	"126.0.0.0",	7,	1	},
		{ "1.2.3.4",	"0.0.0.0",	0,	1	},
		{ "1.2.3.4",	"1.2.2.0",	23,	1	},
		{ "1.2.4.4",	"1.2.2.0",	23,	0	},
	};

	vector<address_test> const ipv6_address_tests{
		{ "::1",		"::1",		128,	1	},
		{ "::2",		"::1",		128,	0	},
		{ "::1",		"::",		0,	1	},
		{ "3ffd::1",		"3ffe::",	16,	0	},
		{ "3ffd::1",		"3ffe::",	15,	0	},
		{ "3ffe::1",		"3ffe::",	16,	1	},
		{ "3fff::1",		"3ffe::",	15,	1	},
		{ "2000:db8::1",	"2000::",	4,	1 	},
		{ "2800::1",		"2000::",	5,	0 	},
		{ "2000:7fff::1",	"2000::",	17,	1	},
		{ "2000:8000::1",	"2000::",	17,	0	},
	};

	struct basic_test {
		string	field;
		string	user;
		string	password;
		int	expect;
	};

	vector<basic_test> const basic_tests{
		{ "Basic dXNlcjpwYXNzd29yZA==",	"user",	  "password",	1 },
		{ "Basic dXNlcjpwYXNzd29yZA==",	"xuser",  "password",	0 },
		{ "Basic dXNlcjpwYXNzd29yZA==",	"user",	  "xpassword",	0 },
		{ "Basic dXNlcjo=",		"user",   "",		1 },
		{ "Basic OnBhc3N3b3Jk",		"",       "password",	1 },
	};

} // anonymous namespace

TEST(Auth, IPv4Network)
{
	for (address_test test: ipv4_address_tests) {
		in_addr_t ip, net;

		ASSERT_EQ(1, inet_pton(AF_INET, test.ip.c_str(), &ip));
		ASSERT_EQ(1, inet_pton(AF_INET, test.network.c_str(), &net));
		EXPECT_EQ(test.expect,
			  ipv4_in_network(ip, net, test.prefix_length))
			<< "address " << test.ip 
			<< ", network " << test.network
			<< "/" << test.prefix_length;
	}
}

TEST(Auth, IPv6Network)
{
	for (address_test test: ipv6_address_tests) {
		struct in6_addr ip, net;

		ASSERT_EQ(1, inet_pton(AF_INET6, test.ip.c_str(), &ip));
		ASSERT_EQ(1, inet_pton(AF_INET6, test.network.c_str(), &net));
		EXPECT_EQ(test.expect,
			  ipv6_in_network(&ip, &net, test.prefix_length))
			<< "address " << test.ip 
			<< ", network " << test.network
			<< "/" << test.prefix_length;
	}
}

TEST(Auth, Basic)
{
	for (basic_test test: basic_tests) {
		remap_path_t test_rp;

		std::memset(&test_rp, 0, sizeof(test_rp));
		test_rp.rp_auth_type = REMAP_AUTH_BASIC;
		test_rp.rp_users = hash_new(127, NULL);

		string cryptpw = "{PLAIN}" + test.password;
		hash_set(test_rp.rp_users, test.user.c_str(),
			 const_cast<void *>(static_cast<void const *>(
					 cryptpw.c_str())));

		EXPECT_EQ(test.expect,
			  auth_check_basic(test.field.data(),
				  	   test.field.size(),
				  	   &test_rp))
			<< "field [" << test.field << "], "
			<< "username [" << test.user << "], "
			<< "password [" << test.password << "]";

		hash_free(test_rp.rp_users);
	}
}

