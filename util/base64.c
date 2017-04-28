/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2011, 2017 Felicity Tarnell.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<string.h>
#include	<stdlib.h>
#include	<stdio.h>

#include	"base64.h"

static char b64table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define	b64untable(c)							\
	( ((c) >= 'A' && (c) <= 'Z') ? ((c) - 'A')			\
	: ((c) >= 'a' && (c) <= 'z') ? (((c) - 'a') + 26)		\
	: ((c) >= '0' && (c) <= '9') ? (((c) - '0') + 52)		\
	: ((c) == '+') ? 62						\
	: ((c) == '/') ? 63						\
	: ((c) == '=') ? 0						\
	: -1)								\

/*
 * Encode the given inbuf, which is inlen bytes long, as base64 and write the
 * result to outbuf, which must be large enough to hold the output.  Use
 * base64_encode_len(inlen) to determine the size of the output.
 *
 * base64_encode cannot fail.
 */
void
base64_encode(const unsigned char *inbuf, size_t inlen, char *outbuf)
{
size_t	left = inlen;

	while (left > 0) {
	unsigned char	d[4] = {};
	int		todo = left > 3 ? 3 : left;

		switch (todo) {
		case 3:
			d[3] |= (inbuf[2] & 0x3F);
			d[2] |= ((inbuf[2] & 0xC0) >> 6);
		case 2:
			d[2] |= (inbuf[1] & 0x0F) << 2;
			d[1] |= ((inbuf[1] & 0xF0) >> 4);
		case 1:
			d[0] = (inbuf[0] & 0xFC) >> 2;
			d[1] |= (inbuf[0] & 0x03) << 4;
		}

		*outbuf++ = b64table[d[0]];
		*outbuf++ = b64table[d[1]];

		if (todo >= 3) {
			*outbuf++ = b64table[d[2]];
			*outbuf++ = b64table[d[3]];
		} else if (todo == 2) {
			*outbuf++ = b64table[d[2]];
			*outbuf++ = '=';
		} else if (todo == 1) {
			*outbuf++ = '=';
			*outbuf++ = '=';
		}

		left -= todo;
		inbuf += todo;
	}
}

/*
 * Decode the given inbuf, which contains inlen bytes of base64 data, and write
 * the result to outbuf.  outbuf must be large enough to hold the output; use
 * base64_encode_len(inlen) to determine the maximum size of the output.
 *
 * Returns the actual length of the decoded data (which may be less than
 * base64_encode_len(inlen)), or -1 if invalid base64 encoding was detected.
 */
ssize_t
base64_decode(char const *inbuf, size_t inlen, unsigned char *outbuf)
{
unsigned const char	*p = (unsigned const char *)inbuf,
	 		*end = p + inlen;
ssize_t			 nbytes = 0;

	while ((end - p) >= 4) {
	unsigned char	d[3];
	int		padding = 0;

		if (p[3] == '=') ++padding;
		if (p[2] == '=') ++padding;

		if (p[1] == '=' || p[0] == '=')
			return -1;

		if (padding && ((end - p) > 4))
			return -1;

		if (b64untable(p[3]) == -1) return -1;
		if (b64untable(p[2]) == -1) return -1;
		if (b64untable(p[1]) == -1) return -1;
		if (b64untable(p[0]) == -1) return -1;

		d[2]  =  b64untable(p[3]) & 0x3F;
		d[2] |= (b64untable(p[2]) & 0x03) << 6;
		d[1]  = (b64untable(p[2]) & 0x3C) >> 2;
		d[1] |= (b64untable(p[1]) & 0x0F) << 4;
		d[0]  = (b64untable(p[1]) & 0x30) >> 4;
		d[0] |=  b64untable(p[0])         << 2;

		bcopy(d, outbuf, (3 - padding));
		nbytes += (3 - padding);

		if (padding)
			break;

		outbuf += 3;
		p += 4;
	}

	return nbytes;
}

