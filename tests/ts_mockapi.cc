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
 * Mock some TS API functions that we use in testing.
 */

#include	<cstdarg>
#include	<cstdio>
#include	<cstring>
#include	<string.h>	// for strdup

#include	<openssl/ssl.h>
#include	<openssl/err.h>

#include	<ts/ts.h>

#include	"tests/test.h"

extern "C" {

int ts_api_errors;

void
TSError(char const *fmt, ...)
{
va_list	args;
	va_start(args, fmt);
	std::fputs("[    TSAPI ] ", stderr);
	std::vfprintf(stderr, fmt, args);
	std::fputs("\n", stderr);
	va_end(args);

	++ts_api_errors;
}

void
TSDebug(char const *tag, char const *fmt, ...)
{
}

void
TSSslContextDestroy(TSSslContext ctx)
{
	SSL_CTX *sslctx = reinterpret_cast<SSL_CTX *>(ctx);
	SSL_CTX_free(sslctx);
}

const char *
TSConfigDirGet(void)
{
	/* Not actually used for anything in tests. */
	return "/usr/local/etc";
}

TSSslContext
TSSslServerContextCreate(void)
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
	return reinterpret_cast<TSSslContext>(ctx);
}

char *
_k8s_get_ssl_error(void)
{
BIO	*bio = BIO_new(BIO_s_mem());
size_t	 len;
char	*ret, *buf;

	ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &buf);
	if (len == 0) {
		BIO_free(bio);
		return strdup("no error");
	}

	if ((ret = static_cast<char *>(malloc(len + 1))) == NULL) {
		BIO_free(bio);
		return NULL;
	}

	std::memcpy(ret, buf, len);
	buf[len] = '\0';
	BIO_free(bio);
	return ret;
}
}	// extern "C"
