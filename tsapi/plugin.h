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

#include	<unistd.h>
#include	<regex.h>

#include	<ts/ts.h>
#include	<zlib.h>

#include	"brotli/encode.h"
#include	"hash.h"
#include	"api.h"
#include	"watcher.h"
#include	"remap.h"
#include	"config.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char *via_name;
extern int via_name_len;
extern char myhostname[HOST_NAME_MAX + 1];

/*
 * Hold the current Kubernetes cluster state (populated by our watchers), as
 * well as the TLS map and remap maps.
 */
struct state {
	pthread_rwlock_t	 lock;
	k8s_config_t		*config;

	/* current cluster state */
	cluster_t		*cluster;
	watcher_t		*watcher;
	remap_db_t		*db;

	TSCont			 tls_cont;
	TSCont			 remap_cont;

	/*
	 * TS config slot that our configuration is stored in.  This can be
	 * passed to TSConfigGet() to fetch the current configuration (as a
	 * struct remap_db *) in a thread-safe way.
	 */
	int		 cfg_slot;
};

int	handle_remap(TSCont, TSEvent, void *);
int	handle_tls(TSCont, TSEvent, void *);
void	rebuild_maps(void);

extern struct state *state;

/*
 * Compression state.
 */
#define	COMP_NONE	0
#define	COMP_GZIP	1
#define	COMP_BROTLI	2

struct comp_state;

typedef void (*comp_init_callback) (struct comp_state *);
typedef int64_t (*comp_produce_callback) (struct comp_state *,
					  unsigned const char *, size_t);
typedef int64_t (*comp_finish_callback) (struct comp_state *);
typedef void (*comp_free_callback) (struct comp_state *);

typedef struct comp_state {
	TSHttpTxn	cs_txn;
	int		cs_type;
	hash_t		cs_types;

	/* The VIO that's writing to us */
	TSVIO			cs_input_vio;
	TSIOBufferReader	cs_input_reader;

	/* The VIO we're writing to */
	int64_t			cs_output_len;
	TSIOBuffer		cs_output_buffer;
	TSIOBufferReader	cs_output_reader;
	TSVIO			cs_output_vio;
	TSCont			cs_output_conn;

	int			cs_done_init:1;

	/* callbacks */
	comp_init_callback	cs_init;
	comp_produce_callback	cs_produce;
	comp_finish_callback	cs_finish;
	comp_free_callback	cs_free;

	/* compression state */
	union {
		z_stream		 cs_zstream;
		BrotliEncoderState	*cs_brotli;
	};
} comp_state_t;

struct request_ctx;

void	tsi_compress(struct request_ctx *, remap_path_t *rp, TSHttpTxn txn);
int	comp_check_compress(TSCont contn, TSEvent event, void *edata);
int	comp_remove_aenc(TSCont contn, TSEvent event, void *edata);
int	comp_check_cached_response(TSCont contn, TSEvent event, void *edata);
int	comp_check_server_response(TSCont contn, TSEvent event, void *edata);
int	comp_set_compress_headers(TSCont contn, TSEvent event, void *edata);
int	comp_set_content_encoding(TSCont contn, TSEvent event, void *edata);
void	comp_state_free(comp_state_t *cs);

/*
 * Request state; this persists though the entire connection.
 */
typedef struct request_ctx {
	unsigned int	 rq_compress:1;
	comp_state_t	*rq_comp_state;
	TSCont		 rq_compress_transform;

	unsigned int	 rq_server_push:1;
	unsigned int	 rq_cache_enabled:1;
	unsigned int	 rq_can_cache:1;

	hash_t		 rq_response_headers;
} request_ctx_t;

void request_ctx_free(request_ctx_t *);
#ifdef __cplusplus
}
#endif

#endif  /* !KUBERNETES_PLUGIN_H */
