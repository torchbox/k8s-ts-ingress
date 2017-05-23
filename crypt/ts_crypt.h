/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	CRYPT_H
#define	CRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*crypt_fn_t) (const char *plain, const char *salt,
			   char *buf, size_t n);

int	 crypt_check(const char *plain, const char *hash);

int	 crypt_des(const char *, const char *, char *, size_t);
int	 crypt_md5(const char *, const char *, char *, size_t);
int	 crypt_blowfish(const char *, const char *, char *, size_t);
int	 crypt_sha256(const char *, const char *, char *, size_t);
int	 crypt_sha512(const char *, const char *, char *, size_t);

typedef int (*crypt_check_fn) (const char *, const char *);

int	crypt_check_des(const char *plain, const char *hashed);
int	crypt_check_phk_md5(const char *plain, const char *hashed);
int	crypt_check_blowfish(const char *plain, const char *hashed);
int	crypt_check_sha256(const char *plain, const char *hashed);
int	crypt_check_sha512(const char *plain, const char *hashed);
int	crypt_check_rfc2307_plain(const char *plain, const char *hashed);
int	crypt_check_rfc2307_sha(const char *plain, const char *hashed);
int	crypt_check_rfc2307_ssha(const char *plain, const char *hashed);

#ifdef __cplusplus
}
#endif

#endif	/* !CRYPT_H */
