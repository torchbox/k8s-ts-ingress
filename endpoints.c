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

#include	<json.h>

#include	"api.h"

void
endpoints_port_free(endpoints_port_t *et)
{
	free(et->et_name);
	free(et->et_protocol);
	free(et);
}

void
endpoints_free(endpoints_t *eps)
{
size_t	i, j;
	free(eps->ep_name);
	free(eps->ep_namespace);

	for (i = 0; i < eps->ep_nsubsets; i++) {
		for (j = 0; j < eps->ep_subsets[i].es_naddrs; j++) {
			free(eps->ep_subsets[i].es_addrs[j].ea_ip);
			free(eps->ep_subsets[i].es_addrs[j].ea_nodename);
		}

		free(eps->ep_subsets[i].es_addrs);
		hash_free(eps->ep_subsets[i].es_ports);
	}

	free(eps->ep_subsets);
	free(eps);
}

endpoints_t *
endpoints_make(json_object *obj)
{
endpoints_t		*eps = NULL;
json_object		*metadata, *tmp, *subsets;
size_t			 i, j;

	if ((eps = calloc(1, sizeof(*eps))) == NULL)
		return NULL;

	/* Endpoints.metadata */
	if (!json_object_object_get_ex(obj, "metadata", &metadata)
	    || !json_object_is_type(metadata, json_type_object))
		goto error;

	/* Endpoints.metadata.namespace */
	if (!json_object_object_get_ex(metadata, "namespace", &tmp)
	    || !json_object_is_type(tmp, json_type_string))
		goto error;
	eps->ep_namespace = strdup(json_object_get_string(tmp));

	/* Endpoints.metadata.name */
	if (!json_object_object_get_ex(metadata, "name", &tmp)
	    || !json_object_is_type(tmp, json_type_string))
		goto error;
	eps->ep_name = strdup(json_object_get_string(tmp));

	/* Endpoints.metadata.subsets */
	if (!json_object_object_get_ex(obj, "subsets", &subsets)
	    || !json_object_is_type(subsets, json_type_array))
		return eps;
	
	eps->ep_nsubsets = json_object_array_length(subsets);
	eps->ep_subsets = calloc(eps->ep_nsubsets, sizeof(endpoints_subset_t));

	/* for each subset */
	for (i = 0; i < eps->ep_nsubsets; i++) {
	json_object	*subset = json_object_array_get_idx(subsets, i),
			*ports, *addresses;

		eps->ep_subsets[i].es_ports = hash_new(7, (hash_free_fn) 
						       endpoints_port_free);

		/* Endpoints.metadata.subsets.ports */
		if (json_object_object_get_ex(subset, "ports", &ports)
		    && json_object_is_type(ports, json_type_array)) {
		size_t	nports = json_object_array_length(ports);

			/* for each port */
			for (j = 0; j < nports; j++) {
			json_object		*port = json_object_array_get_idx(ports, j);
			endpoints_port_t	*eport;

				eport = calloc(1, sizeof(*eport));

				/* Endpoints.metadata.subsets.port.name */
				if (json_object_object_get_ex(port, "name", &tmp)
				    && json_object_is_type(tmp, json_type_string)) {
					eport->et_name = strdup(
						json_object_get_string(tmp));
				} else {
					eport->et_name = strdup("");
				}

				/* Endpoints.metadata.subsets.port.protocol */
				if (json_object_object_get_ex(port, "protocol", &tmp)
				    && json_object_is_type(tmp, json_type_string)) {
					eport->et_protocol = strdup(
						json_object_get_string(tmp));
				} else {
					eport->et_protocol = strdup("");
				}

				/* Endpoints.metadata.subsets.port.port */
				if (json_object_object_get_ex(port, "port", &tmp)
				    && json_object_is_type(tmp, json_type_int)) {
					eport->et_port = json_object_get_int(tmp);
				}

				hash_set(eps->ep_subsets[i].es_ports,
					 eport->et_name, eport);
			}
		}

		/* Endpoints.metadata.subsets.addresses */
		if (json_object_object_get_ex(subset, "addresses", &addresses)
		    && json_object_is_type(addresses, json_type_array)) {

			eps->ep_subsets[i].es_naddrs = 
				json_object_array_length(ports);
			eps->ep_subsets[i].es_addrs = calloc(
						eps->ep_subsets[i].es_naddrs,
						sizeof(endpoints_address_t));

			/* for each address */
			for (j = 0; j < eps->ep_subsets[i].es_naddrs; j++) {
			endpoints_address_t	*eaddr = 
				&eps->ep_subsets[i].es_addrs[j];
			json_object		*address =
				json_object_array_get_idx(addresses, j);

				/* Endpoints.metadata.subsets.address.ip */
				if (json_object_object_get_ex(address, "ip", &tmp)
				    && json_object_is_type(tmp, json_type_string)) {
					eaddr->ea_ip = strdup(
						json_object_get_string(tmp));
				}

				/* Endpoints.metadata.subsets.address.nodeName */
				if (json_object_object_get_ex(address,
							      "nodeName",
							      &tmp)
				    && json_object_is_type(tmp,
							   json_type_string)) {
					eaddr->ea_nodename = strdup(
						json_object_get_string(tmp));
				}
			}
		}
	}

	return eps;

error:
	endpoints_free(eps);
	return NULL;
}
