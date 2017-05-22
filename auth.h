/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef AUTH_H
#define AUTH_H

#include    <sys/types.h>
#include    <sys/socket.h>
#include    <netinet/in.h>

#include    "hash.h"
#include    "plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

struct remap_path;

int auth_check_password(hash_t users, const char *usenam, const char *pass);
int auth_check_basic(const char *hdr, size_t hdrlen, const struct remap_path *);
int auth_check_address(const struct sockaddr *addr, const struct remap_path *);

int ipv4_in_network(in_addr_t ip, in_addr_t netw, int pfxlen);
int ipv6_in_network(const struct in6_addr *ip, const struct in6_addr *net,
                    int pfxlen);

#ifdef __cplusplus
}
#endif

#endif  /* !AUTH_H */
