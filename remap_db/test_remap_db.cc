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
 * Tests for remap_db.c: the remap database.
 */

#include	<string>
#include	<vector>
#include	<map>
#include	<cstring>

#include	"remap.h"

#include	"gtest/gtest.h"
#include	"tests/test.h"

using std::vector;
using std::map;
using std::string;
using std::pair;


TEST(RemapDB, PathLookup)
{
	vector<string> paths{
		"/foo",
		"/bar/.*/baz",
	};

	vector<pair<string, string>> path_tests{
		/* Note that when looking up paths, there is no leading '/' */

		/* path			should match */
		{ "foo",		"/foo"		},
		{ "bar",		"<default>",	},
		{ "bar/foo",		"<default>"	},
		{ "bar/foo/baz",	"/bar/.*/baz"	},
	};

	remap_host_t *host = remap_host_new();

	/*
	 * Add some paths to the database.  We (mis)use rp_app_root to record what
	 * the actual path is.
	 */
	for (string path: paths) {
		remap_path_t *rp = remap_host_new_path(host, path.c_str());
		ASSERT_NE(static_cast<remap_path_t *>(nullptr), rp)
			<< "creating path [" << path << "]";

		rp->rp_app_root = strdup(path.c_str());
	}

	/* Mark the default path */
	remap_path_t *defpath = remap_host_get_default_path(host);
	defpath->rp_app_root = strdup("<default>");

	/*
	 * For each test vector, ensure it does or doesn't match.
	 */
	for (auto test: path_tests) {
		remap_path_t *rp;

		rp = remap_host_find_path(host, test.first.c_str(), nullptr);
		EXPECT_STREQ(test.second.c_str(), rp->rp_app_root);
	}

	remap_host_free(host);
}

TEST(RemapDB, HostLookup)
{
	vector<pair<string, remap_host_t *>> hosts{
		{ "example.com",			nullptr },
		{ "foo.example.com",			nullptr },
		{ "bar.foo.example.com",		nullptr },
		{ "example.com.otherdomain.com",	nullptr },
	};

	remap_db_t *db = remap_db_new();

	for (auto &host: hosts)
		host.second = remap_db_get_or_create_host(db, host.first.c_str());

	for (auto &host: hosts)
		EXPECT_EQ(host.second, remap_db_get_host(db, host.first.c_str()));

	remap_db_free(db);
}

TEST(RemapDB, Basic)
{
	json_object *obj;

	cluster_t *cluster = cluster_make();
	namespace_t *ns = cluster_get_namespace(cluster, "default");

	obj = test_load_json("tests/1-basic/endpoints.json");
	namespace_put_endpoints(ns, endpoints_make(obj));
	json_object_put(obj);

	obj = test_load_json("tests/1-basic/service.json");
	namespace_put_service(ns, service_make(obj));
	json_object_put(obj);

	obj = test_load_json("tests/1-basic/ingress.json");
	namespace_put_ingress(ns, ingress_make(obj));
	json_object_put(obj);

	remap_db_t *db = remap_db_from_cluster(cluster);
	ASSERT_TRUE(db != nullptr);

	/* fetch our host */
	remap_host_t *rh = remap_db_get_host(db, "echoheaders.gce.t6x.uk");
	ASSERT_TRUE(rh != nullptr);

	/* fetch the path from this host */
	remap_path_t *rp = remap_host_find_path(rh, "/what/ever", nullptr);
	ASSERT_TRUE(rp != nullptr);

	/* the path should have one address... */
	ASSERT_EQ(1u, rp->rp_naddrs);
	/* ... and it should be this one: */
	ASSERT_STREQ("172.28.100.135:8080", rp->rp_addrs[0]);

	remap_db_free(db);
	cluster_free(cluster);
}
