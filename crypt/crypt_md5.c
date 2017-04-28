/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

#include    <sys/types.h>

#include    <string.h>
#include    <stdio.h>

#include    <openssl/md5.h>

#include    "ts_crypt.h"

/* 0 ... 63 => ascii - 64 */
static unsigned char itoa64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static char *
to64(unsigned long v, int n)
{
	static char buf[5];
	char *s = buf;

	if (n > 4)
		return (NULL);

	memset(buf, '\0', sizeof(buf));
	while (--n >= 0) {
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}

	return (buf);
}

int
crypt_md5(const char *pw, const char *salt, char *passwd, size_t pwlen)
{
	static char salt_copy[9], *p;
	static const char *sp, *ep;
	unsigned char final[16];
	int sl, pl, i, j;
	MD5_CTX	ctx, ctx1;
	unsigned long l;
    const char *magic;

    if (pwlen < 120)
        return -1;

	/* Refine the Salt first */
	sp = salt;

    /* Detect the format based on magic */
    if (strncmp(sp, "$1$", 3) == 0)
        magic = "$1$";
    else if (strncmp(sp, "$apr1$", 6) == 0)
        magic = "$apr1$";
    else
        return -1;

    sp += strlen(magic);

	/* It stops at the first '$', max 8 chars */
	for (ep = sp; *ep != '$'; ep++) {
		if (*ep == '\0' || ep >= (sp + 8))
			return -1;
	}

	/* get the length of the true salt */
	sl = ep - sp;

	/* Stash the salt */
	memcpy(salt_copy, sp, sl);
	salt_copy[sl] = '\0';

	MD5_Init(&ctx);

	/* The password first, since that is what is most unknown */
	MD5_Update(&ctx, pw, strlen(pw));

	/* Then our magic string */
	MD5_Update(&ctx, magic, strlen(magic));

	/* Then the raw salt */
	MD5_Update(&ctx, sp, sl);

	/* Then just as many characters of the MD5(pw, salt, pw) */
	MD5_Init(&ctx1);
	MD5_Update(&ctx1, pw, strlen(pw));
	MD5_Update(&ctx1, sp, sl);
	MD5_Update(&ctx1, pw, strlen(pw));
	MD5_Final(final, &ctx1);

	for(pl = strlen(pw); pl > 0; pl -= 16)
		MD5_Update(&ctx, final, pl > 16 ? 16 : pl);

	/* Don't leave anything around in vm they could use. */
	memset(final, '\0', sizeof final);

	/* Then something really weird... */
	for (j = 0, i = strlen(pw); i != 0; i >>= 1)
		if (i & 1)
			MD5_Update(&ctx, final + j, 1);
		else
			MD5_Update(&ctx, pw + j, 1);

	/* Now make the output string */
	snprintf(passwd, pwlen, "%s%s$", magic, salt_copy);

	MD5_Final(final, &ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i = 0; i < 1000; i++) {
		MD5_Init(&ctx1);
		if (i & 1)
			MD5_Update(&ctx1, pw, strlen(pw));
		else
			MD5_Update(&ctx1, final, 16);

		if (i % 3)
			MD5_Update(&ctx1, sp, sl);

		if (i % 7)
			MD5_Update(&ctx1, pw, strlen(pw));

		if (i & 1)
			MD5_Update(&ctx1, final, 16);
		else
			MD5_Update(&ctx1, pw, strlen(pw));

		MD5_Final(final, &ctx1);
	}

	p = passwd + strlen(passwd);

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12];
	strcat(passwd, to64(l, 4));
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13];
	strcat(passwd, to64(l, 4));
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14];
	strcat(passwd, to64(l, 4));
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15];
	strcat(passwd, to64(l, 4));
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5];
	strcat(passwd, to64(l, 4));
	l =                    final[11]                ;
	strcat(passwd, to64(l, 2));

	/* Don't leave anything around in vm they could use. */
	memset(final, 0, sizeof(final));
	memset(salt_copy, 0, sizeof(salt_copy));
	memset(&ctx, 0, sizeof(ctx));
	memset(&ctx1, 0, sizeof(ctx1));
	(void)to64(0, 4);

	return 0;
}
