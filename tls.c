/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<getopt.h>

#include	<ts/ts.h>
#include	<ts/apidefs.h>
#include	<ts/remap.h>

#include	<openssl/ssl.h>

#include	<json.h>

#include	"hash.h"
#include	"api.h"
#include	"watcher.h"
#include	"config.h"
#include	"plugin.h"
#include	"tls.h"

int
handle_tls(TSCont contn, TSEvent evt, void *edata)
{
TSVConn			 ssl_vc = edata;
SSL			*ssl = (SSL *)TSVConnSSLConnectionGet(ssl_vc);
const char		*host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
const remap_host_t	*rh;
TSConfig		 db_cfg = NULL;
const remap_db_t	*db;
struct state		*state = TSContDataGet(contn);

	/* Host can sometimes be null; do nothing in that case. */
	if (!host)
		goto cleanup;

	TSDebug("kubernetes_tls", "doing SNI map for [%s]", host);

	db_cfg = TSConfigGet(state->cfg_slot);
	db = TSConfigDataGet(db_cfg);

	/* Not initialised yet? */
	if (!db)
		goto cleanup;

	if ((rh = remap_db_get_host(db, host)) == NULL) {
		TSDebug("kubernetes", "[%s] TLS SNI: host not found", host);
		goto cleanup;
	}

	if (!rh->rh_ctx) {
		TSDebug("kubernetes", "[%s] TLS SNI: host found, but not ctx",
			host);
		goto cleanup;
	}

	SSL_set_SSL_CTX(ssl, rh->rh_ctx);
	TSVConnReenable(ssl_vc);

cleanup:
	if (db_cfg)
		TSConfigRelease(state->cfg_slot, db_cfg);
	return TS_SUCCESS;
}

SSL_CTX *
secret_make_ssl_ctx(secret_t *secret)
{
SSL_CTX		*ctx = NULL;
const char	*certstr, *keystr;
BIO		*cert_bio = NULL, *key_bio = NULL, *tmp_bio;
X509		*cert;
EVP_PKEY	*key;
char		 buf[1024];
int		 n;

	if ((certstr = hash_get(secret->se_data, "tls.crt")) == NULL) {
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: no cert",
			secret->se_namespace, secret->se_name);
		return NULL;
	}

	if ((keystr = hash_get(secret->se_data, "tls.key")) == NULL) {
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: no key",
			secret->se_namespace, secret->se_name);
		return NULL;
	}

	if ((ctx = (SSL_CTX *)TSSslServerContextCreate()) == NULL) {
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: SSL_CTX_new failed",
			secret->se_namespace, secret->se_name);
		goto error;
	}

	if ((tmp_bio = BIO_new_mem_buf((char *)certstr, -1)) == NULL) {
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: BIO_new failed",
			secret->se_namespace, secret->se_name);
		goto error;
	}

	tmp_bio = BIO_push(BIO_new(BIO_f_base64()), tmp_bio);
	BIO_set_flags(tmp_bio, BIO_FLAGS_BASE64_NO_NL);

	cert_bio = BIO_new(BIO_s_mem());
	while ((n = BIO_read(tmp_bio, buf, sizeof(buf))) > 0)
		BIO_write(cert_bio, buf, n);
	BIO_free(tmp_bio);

	if ((cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) == NULL) {
	char	*err = _k8s_get_ssl_error();
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: "
			"PEM_read_bio_X509_AUX failed: %s",
			secret->se_namespace, secret->se_name, err);
		free(err);
		goto error;
	}

	if (SSL_CTX_use_certificate(ctx, cert) != 1) {
		X509_free(cert);
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: "
			"SSL_CTX_use_certificate failed",
			secret->se_namespace, secret->se_name);
		goto error;
	}

	while ((cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL) {
		if (SSL_CTX_add_extra_chain_cert(ctx, cert) != 1) {
			TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: "
				"SSL_CTX_add_extra_chain_cert failed",
				secret->se_namespace, secret->se_name);
			goto error;
		}
	}

	BIO_free(cert_bio);
	cert_bio = NULL;

	if ((tmp_bio = BIO_new_mem_buf((char *)keystr, -1)) == NULL) {
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: BIO_new failed",
			secret->se_namespace, secret->se_name);
		goto error;
	}

	tmp_bio = BIO_push(BIO_new(BIO_f_base64()), tmp_bio);
	BIO_set_flags(tmp_bio, BIO_FLAGS_BASE64_NO_NL);

	key_bio = BIO_new(BIO_s_mem());
	while ((n = BIO_read(tmp_bio, buf, sizeof(buf))) > 0)
		BIO_write(key_bio, buf, n);
	BIO_free(tmp_bio);

	if ((key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL)) == NULL) {
		TSError("[kubernetes_tls] cannot read private key");
		goto error;
	}

	if (SSL_CTX_use_PrivateKey(ctx, key) != 1) {
		EVP_PKEY_free(key);
		TSDebug("kubernetes_api", "secret_make_ssl_ctx %s/%s: "
			"SSL_CTX_use_PrivateKey failed",
			secret->se_namespace, secret->se_name);
		goto error;
	}

	return ctx;

error:
    if (cert_bio)
        BIO_free(cert_bio);
    if (key_bio)
        BIO_free(key_bio);
    if (ctx)
        SSL_CTX_free(ctx);
    return NULL;
}
