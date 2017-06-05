/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef WATCHER_H
#define WATCHER_H

#include	<json.h>

#include	"api.h"

struct k8s_config;
typedef struct watcher watcher_t;

watcher_t	*watcher_create(struct k8s_config *, cluster_t *cluster);
void		 watcher_free(watcher_t *);
int		 watcher_run(watcher_t *);
void		 watcher_set_callback(watcher_t *, cluster_callback_t, void *);
int		 watcher_set_client_tls(watcher_t *, const char *keyfile, const char *certfile);
int		 watcher_set_client_cafile(watcher_t *, const char *cafile);
int		 watcher_set_client_token(watcher_t *, const char *token);

#endif	/* !WATCHER_H */
