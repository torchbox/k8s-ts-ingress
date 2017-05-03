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
secret_free(secret_t *secret)
{
	hash_free(secret->se_data);
	free(secret->se_type);
	free(secret->se_name);
	free(secret->se_namespace);
	free(secret);
}

secret_t *
secret_make(json_object *obj) 
{
secret_t	*secret = NULL;
json_object	*metadata, *tmp, *data;
json_object_iter iter;

	if ((secret = calloc(1, sizeof(*secret))) == NULL)
		return NULL;

	secret->se_data = hash_new(127, free);

	if (!json_object_object_get_ex(obj, "metadata", &metadata)
	    || !json_object_is_type(metadata, json_type_object)) {
		TSDebug("kubernetes_api", "secret_make: no metadata! (obj: [%s]",
			json_object_get_string(obj));
		goto error;
	}

	if (!json_object_object_get_ex(metadata, "namespace", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSDebug("kubernetes_api", "secret_make: no namespace!");
		goto error;
	}
	secret->se_namespace = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(metadata, "name", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSDebug("kubernetes_api", "secret_make: no name!");
		goto error;
	}
	secret->se_name = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(obj, "type", &tmp)
	    || !json_object_is_type(tmp, json_type_string)) {
		TSDebug("kubernetes_api", "secret_make: no type!");
		goto error;
	}
	secret->se_type = strdup(json_object_get_string(tmp));

	if (!json_object_object_get_ex(obj, "data", &data)) {
		TSDebug("kubernetes_api", "secret_make: %s/%s: no data!",
			secret->se_namespace, secret->se_name);
		return secret;
	}

	if (!json_object_is_type(data, json_type_object)) {
		TSDebug("kubernetes_api", "secret_make: %s/%s: data is no object!",
			secret->se_namespace, secret->se_name);
		return secret;
	}

	json_object_object_foreachC(data, iter) {
		if (!json_object_is_type(iter.val, json_type_string))
			continue;

		hash_set(secret->se_data, iter.key,
			 strdup(json_object_get_string(iter.val)));
	}

	return secret;

error:
	secret_free(secret);
	return NULL;
}

