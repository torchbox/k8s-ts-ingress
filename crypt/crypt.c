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
 * crypt.c: provide password hash checking support, allowing a plaintext
 * password to be validated against a hash.
 *
 * Support is provided for several secure algorithms, as well as some 
 * insecure algorithms which may be used in existing htpasswd files.
 *
 * Supported crypt()-style formats:
 *
 * - UNIX DES, both the traditional version and BSD/OS's extended format.
 *
 * - phk's salted MD5 ($1$).
 *
 * - Apache MD5 ($apr1$), commonly used with htpasswd files.  This uses an
 *   algorithm identical to $1$, but the difference in magic string makes the
 *   resulting hashes incompatible; you can't just change $1$ to $apr1$ or vice
 *   versa.  This is because the magic string becomes part of the hash.
 *
 * - bcrypt in its $2a$, $2b$, $2x$ and $2y$ variants; common on recent
 *   (post-1998) BSD systems. $2$ is obsolete and not supported.
 *
 * - glibc SHA-256 ($5$) and SHA-512 ($6$) formats with optional 'rounds'
 *   parameter; common on Linux systems.
 *
 * In addition, some RFC2307-style hash formats are supported for nginx
 * compatibility:
 *
 * - base64-encoded salted SHA-1, in the format {SSHA}hash.
 *
 * - base64-encoded unsalted SHA-1, in the format {SHA}hash.
 *
 * - any other supported crypt() hash, in the format {CRYPT}hash.
 *
 * - plaintext, in the format {PLAIN}password.
 *
 * Most of the supported algorithms are woefully insecure; even ignoring
 * algorithmic weaknesses, the DES, MD5 and SHA-1 based hashes, salted or not,
 * are fast enough on modern hardware that they can be easily cracked.
 * Unfortunately, many (most?) htpasswd files still use these weak algorithms,
 * so we continue to support them.
 *
 * For new passwords, the bcrypt $2a$ format is recommended:
 *
 * - It uses an established, secure cypher;
 * - Unlike the glibc SHA-2 algorithms, it does not benefit significantly from
 *   GPU-based password crackers;
 * - It is supported by modern versions of Apache HTTPd on all platforms.
 *
 * $2y$ may not be supported by some bcrypt implementations.  In case that
 * matters to you, use $2a$ or $2b$ instead, both of which are secure if
 * implemented correctly.
 *
 * Unfortunately, none of the bcrypt formats are supported by stock glibc,
 * which means they don't work on Linux with nginx (which relies on libc
 * crypt() for hashing).
 *
 * If compatibility with nginx on Linux is needed, then use the glibc SHA-256
 * or SHA-512 formats; this is compatible with Apache HTTPd on Linux, and will
 * also work with HTTPd and nginx on some other platforms (e.g. FreeBSD).
 *
 * If the widest compatibility is required, then use the Apache $apr1$ format.
 * However, this offers very little security. 
 */

#include	<stdlib.h>
#include	<string.h>
#include	<stdio.h>

#include	<openssl/sha.h>

#include	"ts_crypt.h"
#include	"base64.h"

/* UNIX DES; BSD/OS extended DES */
int
crypt_check_des(const char *plain, const char *hashed)
{
char	buf[128];
	crypt_des(plain, hashed, buf, sizeof(buf));
	return strcmp(buf, hashed) == 0;
}

/* phk's multi-round MD5 from FreeBSD */
int
crypt_check_phk_md5(const char *plain, const char *hashed)
{
char	buf[128];
	crypt_md5(plain, hashed, buf, sizeof(buf));
	return strcmp(buf, hashed) == 0;
}

/* Blowfish from OpenBSD */
int
crypt_check_blowfish(const char *plain, const char *hashed)
{
char	buf[128];
	crypt_blowfish(plain, hashed, buf, sizeof(buf));
	return strcmp(buf, hashed) == 0;
}

/* Ulrich Drepped's SHA-256 from glibc */
int
crypt_check_sha256(const char *plain, const char *hashed)
{
char	buf[128];
	crypt_sha256(plain, hashed, buf, sizeof(buf));
	return strcmp(buf, hashed) == 0;
}

/* Ulrich Drepped's SHA-512 from glibc */
int
crypt_check_sha512(const char *plain, const char *hashed)
{
char	buf[128];
	crypt_sha512(plain, hashed, buf, sizeof(buf));
	return strcmp(buf, hashed) == 0;
}

/* RFC2307 "PLAIN" mechanism (not actually a hash) */
int
crypt_check_rfc2307_plain(const char *plain, const char *hashed)
{
	if (strncmp(hashed, "{PLAIN}", 7))
		return 0;

	if (strcmp(hashed + 7, plain))
		return 0;

	return 1;
}

/* RFC2307 unsalted SHA mechanism */
int
crypt_check_rfc2307_sha(const char *plain, const char *hashed)
{
unsigned char	 sha[SHA_DIGEST_LENGTH];
unsigned char	*b;
int		 ret;
ssize_t		 s;

	if (strncmp(hashed, "{SHA}", 5))
		return 0;
	hashed += 5;

	b = calloc(1, base64_decode_len(strlen(hashed)) + 1);

	s = base64_decode(hashed, strlen(hashed), b);
	if (s != SHA_DIGEST_LENGTH) {
		free(b);
		return 0;
	}

	SHA1((unsigned char *)plain, strlen(plain), sha);
	ret = !memcmp(b, sha, SHA_DIGEST_LENGTH);

	free(b);
	return ret;
}

/* RFC2307 salted SHA mechanism */
int
crypt_check_rfc2307_ssha(const char *plain, const char *hashed)
{
unsigned char	 sha[SHA_DIGEST_LENGTH];
unsigned char	*b;
unsigned char	*salt;
char		*pwsalt;
int		 ret;
ssize_t		 s;
size_t		 plainlen, hashlen, saltlen;

	if (strncmp(hashed, "{SSHA}", 6))
		return 0;
	hashed += 6;

	plainlen = strlen(plain);
	hashlen = strlen(hashed);
	b = calloc(1, base64_decode_len(hashlen) + 1);

	s = base64_decode(hashed, hashlen, b);
	if (s <= SHA_DIGEST_LENGTH) {
		free(b);
		return 0;
	}

	salt = b + SHA_DIGEST_LENGTH;
	saltlen = s - SHA_DIGEST_LENGTH;

	pwsalt = malloc(plainlen + saltlen);
	bcopy(plain, pwsalt, plainlen);
	bcopy(salt, pwsalt + plainlen, saltlen);

	SHA1((unsigned char *)pwsalt, plainlen + saltlen, sha);
	ret = !memcmp(b, sha, SHA_DIGEST_LENGTH);

	free(pwsalt);
	free(b);
	return ret;
}

static crypt_check_fn
get_crypt_function(const char *hash)
{
const char	*p;

	/*
	 * A 13-character string that doesn't start with $ or { is a
	 * traditional UNIX DES hash.
	 */
	if (strlen(hash) == 13 && !strchr("${", hash[0]))
		return crypt_check_des;

	/* Extended DES */
	if (hash[0] == '_')
		return crypt_check_des;

	/*
	 * A string starting with a $ and containing one or more additional
	 * $-separated fields is a Modular Crypt Format hash; detect the
	 * format from the first field.
	 */
	if (hash[0] == '$' && (p = strchr(hash + 1, '$'))) {
	const char	*mcf = hash + 1;
	size_t		 n = p - mcf;
		if (n == 4 && !memcmp(mcf, "apr1", 4))
			return crypt_check_phk_md5;
		if (n == 1 && *mcf == '1')
			return crypt_check_phk_md5;
		if (n >= 1 && *mcf == '2')
			return crypt_check_blowfish;
		if (n == 1 && *mcf == '5')
			return crypt_check_sha256;
		if (n == 1 && *mcf == '6')
			return crypt_check_sha512;

		return NULL;
	}

	if (hash[0] == '{' && (p = strchr(hash + 1, '}'))) {
	const char	*fmt = hash + 1;
	size_t		 n = p - fmt;
		if (n == 5 && !memcmp(fmt, "PLAIN", 5))
			return crypt_check_rfc2307_plain;
		if (n == 3 && !memcmp(fmt, "SHA", 3))
			return crypt_check_rfc2307_sha;
		if (n == 4 && !memcmp(fmt, "SSHA", 4))
			return crypt_check_rfc2307_ssha;
	}

	return NULL;
}

int
crypt_check(const char *plain, const char *hash)
{
crypt_check_fn	 crypt_fn;

	/*
	 * Some RFC2307 implementations (e.g. OpenLDAP) support a {CRYPT}
	 * mechanism, with a standard crypt() hash as the payload.  Support that
	 * by stripping the prefix and processing it normally.
	 */
	if (strncmp(hash, "{CRYPT}", 7) == 0)
		hash += 7;

	/*
	 * Find the implementation for this hash format.
	 */
	crypt_fn = get_crypt_function(hash);
	if (!crypt_fn)
		return 0;

	/*
	 * Check the password.
	 */
	return crypt_fn(plain, hash);
}

