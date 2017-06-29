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

#include	<openssl/ssl.h>
#include	<ts/ts.h>

#include	"api.h"
#include	"base64.h"

void
configmap_free(configmap_t *configmap)
{
	hash_free(configmap->cm_data);
	free(configmap->cm_name);
	free(configmap->cm_namespace);
	free(configmap);
}

configmap_t *
configmap_make(json_object *obj) 
{
configmap_t	*configmap = NULL;
json_object	*metadata, *tmp, *data;
json_object_iter iter;

	if ((configmap = calloc(1, sizeof(*configmap))) == NULL)
		return NULL;

	configmap->cm_data = hash_new(127, free);

	if (!json_object_object_get_ex(obj, "metadata", &metadata)
	    || !json_object_is_type(metadata, json_type_object)) {
		TSDebug("kubernetes_api", "configmap_make: no metadata! (obj: [%s]",
			json_object_get_string(obj));
		goto error;
	}

	if (!json_object_object_get_ex(metadata, "namespace", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSDebug("kubernetes_api", "configmap_make: no namespace!");
		goto error;
	}
	configmap->cm_namespace = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(metadata, "name", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSDebug("kubernetes_api", "configmap_make: no name!");
		goto error;
	}
	configmap->cm_name = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(obj, "data", &data)) {
		TSDebug("kubernetes_api", "configmap_make: %s/%s: no data!",
			configmap->cm_namespace, configmap->cm_name);
		return configmap;
	}

	if (!json_object_is_type(data, json_type_object)) {
		TSDebug("kubernetes_api", "configmap_make: %s/%s: data is no object!",
			configmap->cm_namespace, configmap->cm_name);
		return configmap;
	}

	json_object_object_foreachC(data, iter) {
		if (!json_object_is_type(iter.val, json_type_string))
			continue;

		hash_set(configmap->cm_data, iter.key,
			 strdup(json_object_get_string(iter.val)));
	}

	return configmap;

error:
	configmap_free(configmap);
	return NULL;
}
