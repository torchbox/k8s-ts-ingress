/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<string.h>
#include	<stdlib.h>

#include	<ts/ts.h>

#include	"api.h"

void
service_free(service_t *svc)
{
	free(svc->sv_name);
	free(svc->sv_namespace);
	free(svc->sv_type);
	free(svc->sv_cluster_ip);
	free(svc->sv_session_affinity);
	hash_free(svc->sv_selector);
	hash_free(svc->sv_ports);
	free(svc);
}

void
service_port_free(service_port_t *port)
{
	free(port->sp_name);
	free(port);
}

service_t *
service_make(json_object *obj)
{
service_t		*svc;
json_object		*metadata, *spec, *tmp, *ports;
json_object_iter	 iter;

	if ((svc = calloc(1, sizeof(*svc))) == NULL)
		return NULL;

	if (!json_object_object_get_ex(obj, "metadata", &metadata)
	    || !json_object_is_type(metadata, json_type_object)) {
		TSError("[kubernetes] Service has no metadata?");
		goto error;
	}

	if (!json_object_object_get_ex(metadata, "namespace", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSError("[kubernetes] Service has no namespace?");
		goto error;
	}
	svc->sv_namespace = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(metadata, "name", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSError("[kubernetes] Service has no name?");
		goto error;
	}
	svc->sv_name = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(obj, "spec", &spec)
	    || !json_object_is_type(spec, json_type_object)) {
		TSError("[kubernetes] %s/%s: Service has no spec",
			svc->sv_namespace, svc->sv_name);
		return svc;
	}
	
	if (json_object_object_get_ex(spec, "type", &tmp))
		svc->sv_type = strdup(json_object_get_string(tmp));
	if (json_object_object_get_ex(spec, "clusterIP", &tmp))
		svc->sv_cluster_ip = strdup(json_object_get_string(tmp));
	if (json_object_object_get_ex(spec, "sessionAffinity", &tmp))
		svc->sv_session_affinity = strdup(json_object_get_string(tmp));
	if (json_object_object_get_ex(spec, "externalName", &tmp))
		svc->sv_external_name = strdup(json_object_get_string(tmp));

	svc->sv_selector = hash_new(127, free);
	if (json_object_object_get_ex(spec, "selector", &tmp)) {
		json_object_object_foreachC(tmp, iter) {
			hash_set(svc->sv_selector, iter.key,
				 strdup(json_object_get_string(iter.val)));
		}
	}

	svc->sv_ports = hash_new(127, (hash_free_fn) service_port_free);

	if (json_object_object_get_ex(spec, "ports", &ports) &&
	    json_object_is_type(ports, json_type_array)) {
	int	i, n = json_object_array_length(ports);

		for (i = 0; i < n; i++) {
		service_port_t	*port;
		json_object	*jport = json_object_array_get_idx(ports, i);

			port = calloc(1, sizeof(*port));
			if (json_object_object_get_ex(jport, "name", &tmp)
			    && json_object_is_type(tmp, json_type_string)) 
				port->sp_name = strdup(json_object_get_string(tmp));
			else
				port->sp_name = strdup("");

			port->sp_protocol = SV_P_TCP;

			if (json_object_object_get_ex(jport, "protocol", &tmp)
			    && json_object_is_type(tmp, json_type_string)) {
			const char	*proto = json_object_get_string(tmp);
				if (strcmp(proto, "TCP") == 0)
					port->sp_protocol = SV_P_TCP;
				else if (strcmp(proto, "UDP") == 0)
					port->sp_protocol = SV_P_UDP;
			}

			if (json_object_object_get_ex(jport, "port", &tmp)
			    && json_object_is_type(tmp, json_type_int))
				port->sp_port = json_object_get_int(tmp);

			if (json_object_object_get_ex(jport, "targetPort", &tmp)
			    && json_object_is_type(tmp, json_type_int))
				port->sp_target_port = json_object_get_int(tmp);
			else
				port->sp_target_port = port->sp_port;

			hash_set(svc->sv_ports, port->sp_name, port);
		}
	}

	return svc;

error:
	service_free(svc);
	return NULL;
}
