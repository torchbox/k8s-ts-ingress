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

#ifndef WATCHER_H
#define WATCHER_H

#include	<json.h>

struct k8s_config;
typedef struct watcher *watcher_t;

typedef enum {
	WT_ADDED,
	WT_UPDATED,
	WT_DELETED
} wt_event_type_t;

typedef void (*watcher_callback_t) (watcher_t, wt_event_type_t, json_object *, void *);

watcher_t	watcher_create(struct k8s_config *, const char *resource);
int		watcher_run(watcher_t, int);
void		watcher_set_callback(watcher_t, watcher_callback_t, void *);
int		watcher_set_client_tls(watcher_t, const char *keyfile, const char *certfile);
int		watcher_set_client_cafile(watcher_t, const char *cafile);
int		watcher_set_client_token(watcher_t, const char *token);

#endif	/* !WATCHER_H */
