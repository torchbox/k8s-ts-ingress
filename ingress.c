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

#include	<string.h>
#include	<stdlib.h>

#include	<ts/ts.h>

#include	"api.h"

void
ingress_free(ingress_t *ing)
{
size_t	i, j;

	for (i = 0; i < ing->in_nrules; i++) {
		for (j = 0; j < ing->in_rules[i].ir_npaths; j++) {
			free(ing->in_rules[i].ir_paths[j].ip_path);
			free(ing->in_rules[i].ir_paths[j].ip_service_name);
			free(ing->in_rules[i].ir_paths[j].ip_service_port);
		}
		free(ing->in_rules[i].ir_paths);
		free(ing->in_rules[i].ir_host);
	}
	free(ing->in_rules);

	for (i = 0; i < ing->in_ntls; i++) {
	ingress_tls_t	*itls = &ing->in_tls[i];
		free(itls->it_secret_name);

		for (j = 0; j < itls->it_nhosts; j++)
			free(itls->it_hosts[j]);
		free(itls->it_hosts);
	}
	free(ing->in_tls);

	free(ing->in_name);
	free(ing->in_namespace);
	free(ing);
}

static void
ingress_path_make(ingress_path_t *ip, json_object *obj)
{
json_object	*backend, *tmp;

	if (json_object_object_get_ex(obj, "path", &tmp) &&
	    json_object_is_type(tmp, json_type_string))
		ip->ip_path = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(obj, "backend", &backend))
		return;

	if (json_object_object_get_ex(backend, "serviceName", &tmp) &&
	    json_object_is_type(tmp, json_type_string))
		ip->ip_service_name = strdup(json_object_get_string(tmp));

	if (json_object_object_get_ex(backend, "servicePort", &tmp))
		ip->ip_service_port = strdup(json_object_get_string(tmp));
}

static void
ingress_rule_make(ingress_rule_t *ir, json_object *obj)
{
json_object	*tmp, *http, *paths;
size_t		 i;

	/* rule.host */
	if (json_object_object_get_ex(obj, "host", &tmp)
	    && json_object_is_type(tmp, json_type_string))
		ir->ir_host = strdup(json_object_get_string(tmp));

	/* rule.http */
	if (!json_object_object_get_ex(obj, "http", &http))
		return;
	/* rule.http.paths */
	if (!json_object_object_get_ex(http, "paths", &paths))
		return;
	if (!json_object_is_type(paths, json_type_array))
		return;
	
	ir->ir_npaths = json_object_array_length(paths);
	ir->ir_paths = calloc(ir->ir_npaths, sizeof(ingress_path_t));

	for (i = 0; i < ir->ir_npaths; i++)
		ingress_path_make(&ir->ir_paths[i],
				  json_object_array_get_idx(paths, i));
}
	
ingress_t *
ingress_make(json_object *obj)
{
ingress_t	*ing = NULL;
json_object	*metadata, *rules, *tls, *tmp, *spec;

	if ((ing = calloc(1, sizeof(*ing))) == NULL)
		return NULL;

	/* Ingress.metadata */
	if (!json_object_object_get_ex(obj, "metadata", &metadata)
	    || !json_object_is_type(metadata, json_type_object)) {
		TSError("[kubernetes_api] Ingress has no metadata?");
		goto error;
	}

	/* Ingress.metadata.namespace */
	if (!json_object_object_get_ex(metadata, "namespace", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSError("[kubernetes_api] Ingress has no namespace?");
		goto error;
	}
	ing->in_namespace = strdup(json_object_get_string(tmp));

	/* Ingress.metadata.name */
	if (!json_object_object_get_ex(metadata, "name", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSError("[kubernetes_api] Ingress has no name?");
		goto error;
	}
	ing->in_name = strdup(json_object_get_string(tmp));

	/* Ingress.spec */
	if (!json_object_object_get_ex(obj, "spec", &spec)
	    || !json_object_is_type(spec, json_type_object)) {
		TSError("[kubernetes_api] %s/%s: Ingress has no spec",
			ing->in_namespace, ing->in_name);
		return ing;
	}

	/* Ingress.spec.tls */
	if (json_object_object_get_ex(spec, "tls", &tls) &&
	    json_object_is_type(tls, json_type_array)) {
	size_t	i;

		ing->in_ntls = json_object_array_length(tls);
		ing->in_tls = calloc(ing->in_ntls, sizeof(ingress_tls_t));

		/* foreach Ingress.spec.tls */
		for (i = 0; i < ing->in_ntls; i++) {
		json_object	*atls = json_object_array_get_idx(tls, i),
				*hosts, *secretname;
		ingress_tls_t	*itls = &ing->in_tls[i];

			/* Ingress.spec.tls[].secretName */
			if (json_object_object_get_ex(atls, "secretName", &secretname)
			    && json_object_is_type(secretname, json_type_string))
				itls->it_secret_name = strdup(
						json_object_get_string(secretname));

			/* Ingress.spec.tls.hosts[] */
			if (json_object_object_get_ex(atls, "hosts", &hosts)) {
			size_t	j;
				itls->it_nhosts = json_object_array_length(hosts);
				itls->it_hosts = calloc(itls->it_nhosts,
							sizeof(char *));

				for (j = 0; j < itls->it_nhosts; j++) {
				json_object	*host = json_object_array_get_idx(
								hosts, j);
					itls->it_hosts[j] = strdup(
						json_object_get_string(host));
				}
			}
		}
	}

	/* Ingress.spec.rules */
	if (json_object_object_get_ex(spec, "rules", &rules)
	    && json_object_is_type(rules, json_type_array)) {
	size_t	i;

		ing->in_nrules = json_object_array_length(rules);
		ing->in_rules = calloc(ing->in_nrules, sizeof(ingress_rule_t));

		/* foreach Ingress.spec.rules */
		for (i = 0; i < ing->in_nrules; i++) {
			ingress_rule_make(&ing->in_rules[i],
					  json_object_array_get_idx(rules, i));
		}
	}

	return ing;

error:
	ingress_free(ing);
	return NULL;
}
