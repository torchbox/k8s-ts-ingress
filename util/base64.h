/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2011, 2017 Felicity Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef BASE64_H
#define BASE64_H

#include	<stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	base64_encode_len(n)	(4 * ((n + 2) / 3))
#define	base64_decode_len(n)	(3 * ((n + 3) / 4))

void	base64_encode(const unsigned char *inbuf, size_t inlen, char *outbuf);
ssize_t	base64_decode(char const *inbuf, size_t inlen, unsigned char *outbuf);

#ifdef __cplusplus
}
#endif

#endif  /* !BASE64_H */
