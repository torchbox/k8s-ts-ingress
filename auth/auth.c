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
 * auth.c: authentication-related functions.  Nothing here should depend on the
 * TSAPI aside from TSDebug/TSError, to facilitate unit testing.
 */

#include	<string.h>
#include	<ctype.h>

#include	"hash.h"
#include	"ts_crypt.h"
#include	"plugin.h"
#include	"base64.h"

/*
 * Test whether the given plaintext password matches the encrypted password
 * stored in the hash for the given user.
 */
int
auth_check_password(hash_t users, const char *usenam, const char *pass)
{
char	*crypted;
	if ((crypted = hash_get(users, usenam)) == NULL)
		return 0;

	return crypt_check(pass, crypted);
}

/*
 * auth_test_basic: consider whether the given Authorization header value,
 * which is len bytes long, matches a user in the given remap_path's
 * authentication database.  Returns 1 if matched, 0 if not matched, or -1 if
 * the header could not be parsed (or is not a basic authentication header).
 */
int
auth_check_basic(const char *hdr, size_t len, const remap_path_t *rp)
{
char		 buf[256];
char		*creds;
char		*p;
int		 n;
size_t		 credslen;

	if (rp->rp_auth_type != REMAP_AUTH_BASIC)
		return 0;

	if (!rp->rp_users)
		return 0;

	if ((creds = memchr(hdr, ' ', len)) == NULL)
		return -1;

	if (len < 7)
		return -1;

	if (memcmp(hdr, "Basic ", 6))
		return -1;

	while (isspace(*creds) && (creds < hdr + len))
		++creds;

	if (creds == hdr + len)
		return -1;

	credslen = (hdr + len) - creds;

	if (base64_decode_len(credslen) > sizeof(buf) - 1)
		return -1;

	n = base64_decode(creds, credslen, (unsigned char *)buf);

	if (n < 3)
		return -1;

	buf[n] = '\0';

	if ((p = strchr(buf, ':')) == NULL)
		return -1;

	*p++ = '\0';

	if (!auth_check_password(rp->rp_users, buf, p))
		return 0;

	return 1;
}

/*
 * Return 1 if the given IPv4 address is inside the given network (both in
 * network byte order) with prefix length pfxlen, else return 0.
 */
int
ipv4_in_network(in_addr_t ip, in_addr_t net, int pfxlen)
{
	/* Must be uint64_t to avoid shift by 32 when pfxlen is 0 */
uint32_t	mask = ~(uint64_t)0 << (32 - pfxlen);

	if (pfxlen < 0 || pfxlen > 32)
		return 0;

	ip = htonl(ip);
	net = htonl(net);

	return ((ip & mask) == (net & mask));
}

/*
 * Return 1 if the given IPv4 address is inside the given network with prefix
 * length pfxlen, else return 0.
 */
int
ipv6_in_network(const struct in6_addr *ip, const struct in6_addr *net,
		int pfxlen)
{
#define IP6_U32LEN	(128 / 8 / 4)
uint32_t uip[IP6_U32LEN], unet[IP6_U32LEN], mask[IP6_U32LEN];
int	 i;

	if (pfxlen < 0 || pfxlen > 128)
		return 0;

	/* We can't assume the values are aligned, so copy to the stack */
	bcopy(ip->s6_addr, uip, sizeof(uip));
	bcopy(net->s6_addr, unet, sizeof(unet));

	/* Construct a netmask from the given prefix length */
	memset(mask, 0xFF, sizeof(mask));

	i = pfxlen / 32;
	switch (i) {
	case 0: mask[0] = 0;
	case 1: mask[1] = 0;
	case 2: mask[2] = 0;
	case 3: mask[3] = 0;
	}

	if (pfxlen % 32)
		mask[i] = htonl(~(uint32_t)0 << (32 - (pfxlen % 32)));

	/* Check that each 32-bit section of the address matches the network */
	for (i = 0; i < 4; i++)
		if ((uip[i] & mask[i]) != (unet[i] & mask[i]))
			return 0;

	return 1;
#undef	IP6_U32LEN
}

/*
 * auth_check_address: test whether the given IP address is contained in the
 * given route_path's access list.  Returns 1 if so, else 0.
 */
int
auth_check_address(const struct sockaddr *addr, const remap_path_t *rp)
{
struct remap_auth_addr	*rad;

	switch (addr->sa_family) {
	case AF_INET:
		for (rad = rp->rp_auth_addr_list; rad; rad = rad->ra_next) {
		struct sockaddr_in	*sin = (struct sockaddr_in *)addr;

			if (rad->ra_family != AF_INET)
				continue;

			if (ipv4_in_network(sin->sin_addr.s_addr,
					    rad->ra_addr_v4,
					    rad->ra_prefix_length))
				return 1;
		}

		return 0;

	case AF_INET6:
		for (rad = rp->rp_auth_addr_list; rad; rad = rad->ra_next) {
		struct sockaddr_in6	*sin = (struct sockaddr_in6 *)addr;

			if (rad->ra_family != AF_INET6)
				continue;

			if (ipv6_in_network(&sin->sin6_addr,
					    &rad->ra_addr_v6,
					    rad->ra_prefix_length))
				return 1;
		}

		return 0;

	default:
		return 0;
	}
}
