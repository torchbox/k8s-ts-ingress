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

int	 crypt_check(const char *hash, const char *plain);

int	 crypt_des(const char *, const char *, char *, size_t);
int	 crypt_md5(const char *, const char *, char *, size_t);
int	 crypt_blowfish(const char *, const char *, char *, size_t);
int	 crypt_sha256(const char *, const char *, char *, size_t);
int	 crypt_sha512(const char *, const char *, char *, size_t);

#endif	/* !CRYPT_H */
