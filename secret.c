/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<string.h>
#include	<stdlib.h>

#include	<ts/ts.h>

#include	"api.h"

void
secret_free(secret_t *secret)
{
	hash_free(secret->se_data);
	free(secret->se_type);
	free(secret->se_name);
	free(secret->se_namespace);
	free(secret);
}

secret_t *
secret_make(json_object *obj) 
{
secret_t	*secret = NULL;
json_object	*metadata, *tmp, *data;
json_object_iter iter;

	if ((secret = calloc(1, sizeof(*secret))) == NULL)
		return NULL;

	secret->se_data = hash_new(127, free);

	if (!json_object_object_get_ex(obj, "metadata", &metadata)
	    || !json_object_is_type(metadata, json_type_object)) {
		TSDebug("kubernetes_api", "secret_make: no metadata! (obj: [%s]",
			json_object_get_string(obj));
		goto error;
	}

	if (!json_object_object_get_ex(metadata, "namespace", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSDebug("kubernetes_api", "secret_make: no namespace!");
		goto error;
	}
	secret->se_namespace = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(metadata, "name", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSDebug("kubernetes_api", "secret_make: no name!");
		goto error;
	}

	secret->se_name = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(obj, "data", &data)) {
		TSDebug("kubernetes_api", "secret_make: %s/%s: no data!",
			secret->se_namespace, secret->se_name);
		return secret;
	}

	if (!json_object_is_type(data, json_type_object)) {
		TSDebug("kubernetes_api", "secret_make: %s/%s: data is no object!",
			secret->se_namespace, secret->se_name);
		return secret;
	}

	json_object_object_foreachC(data, iter) {
		if (!json_object_is_type(iter.val, json_type_string))
			continue;

		hash_set(secret->se_data, iter.key,
			 strdup(json_object_get_string(iter.val)));
	}

	return secret;

error:
	secret_free(secret);
	return NULL;
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
