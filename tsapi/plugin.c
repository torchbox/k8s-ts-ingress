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
 * plugin.c: provide TS plugin entrypoints, create watchers for the resources
 * we need, and handle keeping the cluster state up to date.
 */

#include	<errno.h>
#include	<string.h>
#include	<unistd.h>
#include	<assert.h>

#include	<json.h>
#include	<curl/curl.h>
#include	<ts/ts.h>

#include	"hash.h"
#include	"watcher.h"
#include	"config.h"
#include	"plugin.h"
#include	"autoconf.h"

char *via_name;
int via_name_len;
char myhostname[HOST_NAME_MAX + 1];

static void cluster_cb(cluster_t *cluster, void *);

struct state *state;

int
tsi_setup_acceptors(TSCont contn, TSEvent event, void *data)
{
int	nps;

	assert(event == TS_EVENT_LIFECYCLE_PORTS_READY);

	/*
	 * To implement selective disabling of HTTP/2 based on hostname, we take
	 * a copy of each acceptor's ProtocolSet, disable HTTP/2 in the copy,
	 * and stash it in state.  To disable HTTP/2 later, we can set our saved
	 * ProtocolSet on the VConn.
	 */

	nps = TSAcceptorCount();
	state->protosets = calloc(nps, sizeof(TSNextProtocolSet));
	for (int i = 0; i < nps; ++i) {
	TSAcceptor	acpt = TSAcceptorGetbyID(i);
		state->protosets[i] = TSGetcloneProtoSet(acpt);
		TSUnregisterProtocol(state->protosets[i],
				     TS_ALPN_PROTOCOL_HTTP_2_0);
	}

	return TS_SUCCESS;
}

/*
 * Initialise plugin, load configuration and start our watchers.
 */
void
TSPluginInit(int argc, const char **argv)
{
TSPluginRegistrationInfo	 info;

	via_name_len = snprintf(NULL, 0, "ATS/%s Ingress/%s",
				TSTrafficServerVersionGet(), PACKAGE_VERSION);
	via_name = malloc(via_name_len + 1);
	via_name_len = snprintf(via_name, via_name_len + 1, "ATS/%s Ingress/%s",
				TSTrafficServerVersionGet(), PACKAGE_VERSION);

	if (gethostname(myhostname, sizeof(myhostname)) == -1)
		strcpy(myhostname, "unknown");

	SSL_library_init();
	SSL_load_error_strings();

	curl_global_init(CURL_GLOBAL_ALL);

	if ((state = calloc(1, sizeof(*state))) == NULL) {
		TSError("[kubernetes] cannot create state: %s",
			strerror(errno));
		return;
	}

	if (argc >= 2)
		state->config = k8s_config_load(argv[1]);
	else
		state->config = k8s_config_load(NULL);

	if (state->config == NULL) {
		TSError("[kubernetes] failed to load configuration");
		return;
	}

	pthread_rwlock_init(&state->lock, NULL);
	state->cluster = cluster_make();

	/*
	 * Create watcher.
	 */
	state->watcher = watcher_create(state->config, state->cluster);
	if (state->watcher == NULL) {
		TSError("[kubernetes] cannot create watcher: %s", strerror(errno));
		return;
	}
	watcher_set_callback(state->watcher, cluster_cb, state);
	watcher_run(state->watcher);

	/*
	 * Create SNI hook to associate Kubernetes SSL_CTXs with incoming
	 * connections.
	 */
	TSDebug("kubernetes", "co_tls=%d", state->config->co_tls);
	if (state->config->co_tls) {
		state->tls_cont = TSContCreate(handle_tls, NULL);
		TSHttpHookAdd(TS_SSL_SNI_HOOK, state->tls_cont);
	}

	/*
	 * Create remap hook to map incoming requests to pods.
	 */
	if (state->config->co_remap) {
		state->remap_cont = TSContCreate(handle_remap, NULL);
		TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, state->remap_cont);
	}

	/*
	 * Add a lifecycle hook to set up our acceptor protocol handling
	 * once network initialisation is done.
	 */
	state->ports_cont = TSContCreate(tsi_setup_acceptors, NULL);
	TSLifecycleHookAdd(TS_LIFECYCLE_PORTS_READY_HOOK, state->ports_cont);

	/*
	 * Register ourselves.
	 */
	info.plugin_name = "Kubernetes Ingress plugin";
	info.vendor_name = "Torchbox, Ltd.";
	info.support_email = "sysadmin@torchbox.com";
	if (TSPluginRegister(&info) != TS_SUCCESS) {
		TSError("[kubernetes] Plugin registration failed.");
		return;
	}
}

static void
cluster_cb(cluster_t *cluster, void *data)
{
	rebuild_maps();
}
