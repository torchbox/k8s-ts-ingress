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
 * Tests for config.c: configuration loader.
 */

#include	<unistd.h>

#include	"config.h"

#include	"gtest/gtest.h"
#include	"tests/test.h"

TEST(Config, Load)
{
	k8s_config_t	*cfg;

	cfg = k8s_config_load("tests/kubernetes.config");
	ASSERT_NE(static_cast<k8s_config_t *>(nullptr), cfg);

	EXPECT_STREQ("https://apiserver.mycluster.com:8443", cfg->co_server);
	EXPECT_STREQ("/path/to/kube-prod.ca", cfg->co_tls_cafile);
	EXPECT_STREQ("/path/to/kube-prod.crt", cfg->co_tls_certfile);
	EXPECT_STREQ("/path/to/kube-prod.key", cfg->co_tls_keyfile);
	EXPECT_EQ(static_cast<const char *>(nullptr), cfg->co_token);
	EXPECT_EQ(1, cfg->co_tls);
	EXPECT_EQ(0, cfg->co_remap);	

	k8s_config_free(cfg);

	setenv("TS_SERVER", "https://other.apiserver.com:7432", 1);
	setenv("TS_CAFILE", "/other/cafile.pem", 1);
	setenv("TS_CERTFILE", "/other/certfile.pem", 1);
	setenv("TS_KEYFILE", "/other/keyfile.pem", 1);
	setenv("TS_TOKEN", "WXYZ9876", 1);
	setenv("TS_TLS", "false", 1);
	setenv("TS_REMAP", "true", 1);

	cfg = k8s_config_load("tests/kubernetes.config");
	ASSERT_NE(static_cast<k8s_config_t *>(nullptr), cfg);

	EXPECT_STREQ("https://other.apiserver.com:7432", cfg->co_server);
	EXPECT_STREQ("/other/cafile.pem", cfg->co_tls_cafile);
	EXPECT_STREQ("/other/certfile.pem", cfg->co_tls_certfile);
	EXPECT_STREQ("/other/keyfile.pem", cfg->co_tls_keyfile);
	EXPECT_EQ(static_cast<const char *>(nullptr), cfg->co_token);
	EXPECT_EQ(0, cfg->co_tls);
	EXPECT_EQ(1, cfg->co_remap);	

	k8s_config_free(cfg);
}

TEST(Config, Invalid1)
{
	k8s_config_t	*cfg;

	ts_api_errors = 0;
	cfg = k8s_config_load("tests/kubernetes.config.invalid");
	ASSERT_EQ(static_cast<k8s_config_t *>(nullptr), cfg);
	EXPECT_EQ(1, ts_api_errors);
}

TEST(Config, Invalid2)
{
	k8s_config_t	*cfg;

	ts_api_errors = 0;
	cfg = k8s_config_load("tests/kubernetes.config.invalid2");
	ASSERT_EQ(static_cast<k8s_config_t *>(nullptr), cfg);
	EXPECT_EQ(1, ts_api_errors);
}

TEST(Config, Invalid3)
{
	k8s_config_t	*cfg;

	ts_api_errors = 0;
	cfg = k8s_config_load("tests/kubernetes.config.nonexistent");
	ASSERT_EQ(static_cast<k8s_config_t *>(nullptr), cfg);
	EXPECT_EQ(1, ts_api_errors);
}
