/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef KUBERNETES_PLUGIN_H
#define KUBERNETES_PLUGIN_H

#include	<regex.h>

#include	<ts/ts.h>

#include	"hash.h"
#include	"api.h"
#include	"watcher.h"

/*
 * Store transient context during rebuild.
 */
struct rebuild_ctx {
	namespace_t	*ns;
	ingress_t	*ingress;
	hash_t		 map;
};

/*
 * Stores one path entry in an Ingress.
 */
struct remap_path {
	char	 *rp_prefix;
	regex_t	  rp_regex;
	char	**rp_addrs;
	size_t	  rp_naddrs;

	int	  rp_cache:1;
	int	  rp_follow_redirects:1;
	int	  rp_hsts_subdomains:1;
	int	  rp_secure_backends:1;
	int	  rp_preserve_host:1;
	int	  rp_cache_gen;
	int	  rp_hsts_max_age;
	char	 *rp_app_root;
	char	 *rp_rewrite_target;
};

/*
 * Store configuration for a particular hostname.  This contains the TLS
 * context, zero or more paths, and maybe a default backend.
 */
struct remap_host {
	struct remap_path	*rh_paths;
	size_t			 rh_npaths;
	struct remap_path	 rh_default;
	SSL_CTX			*rh_ctx;
	int			 rh_no_ssl_redirect:1;
	int			 rh_force_ssl_redirect:1;
};

/*
 * Hold the current Kubernetes cluster state (populated by our watchers), as
 * well as the TLS map and remap maps.
 */
struct state {
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
	 * passed to TSConfigGet() to fetch the current configuration in a
	 * thread-safe way.
	 */
	int		 cfg_slot;
};

int handle_remap(TSCont, TSEvent, void *);
int handle_tls(TSCont, TSEvent, void *);

void rebuild_maps(struct state *);

#endif  /* !KUBERNETES_PLUGIN_H */
