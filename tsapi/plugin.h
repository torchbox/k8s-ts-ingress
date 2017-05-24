/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef KUBERNETES_PLUGIN_H
#define KUBERNETES_PLUGIN_H

#include	<sys/types.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<regex.h>

#include	<ts/ts.h>

#include	"hash.h"
#include	"api.h"
#include	"watcher.h"
#include	"remap.h"
#include	"config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hold the current Kubernetes cluster state (populated by our watchers), as
 * well as the TLS map and remap maps.
 */
struct state {
	k8s_config_t	*config;

	/* current cluster state */
	TSMutex		 cluster_lock;
	cluster_t	*cluster;

	/* watchers */
	watcher_t	 ingress_watcher;
	watcher_t	 secret_watcher;
	watcher_t	 service_watcher;
	watcher_t	 endpoints_watcher;
	/* set to 1 when cluster state changes; set to 0 during rebuild */
	int		 changed;

	TSCont		 rebuild_cont;
	TSCont		 tls_cont;
	TSCont		 remap_cont;

	/*
	 * TS config slot that our configuration is stored in.  This can be
	 * passed to TSConfigGet() to fetch the current configuration (as a
	 * struct remap_db *) in a thread-safe way.
	 */
	int		 cfg_slot;
};

int handle_remap(TSCont, TSEvent, void *);
int handle_tls(TSCont, TSEvent, void *);

void rebuild_maps(struct state *);

#ifdef __cplusplus
}
#endif

#endif  /* !KUBERNETES_PLUGIN_H */
