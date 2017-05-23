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

#include	<openssl/ssl.h>

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

}	// extern "C"
