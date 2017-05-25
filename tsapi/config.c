/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<ctype.h>

#include	<ts/ts.h>

#include	"config.h"

void
k8s_config_free(k8s_config_t *cfg)
{
	if (!cfg)
		return;

	free(cfg->co_server);
	free(cfg->co_tls_certfile);
	free(cfg->co_tls_keyfile);
	free(cfg->co_tls_cafile);
	hash_free(cfg->co_classes);
	free(cfg);
}

void
cfg_set_ingress_classes(k8s_config_t *cfg, const char *classes)
{
char	*s = strdup(classes), *p, *r;

	hash_free(cfg->co_classes);
	cfg->co_classes = hash_new(11, NULL);

	for (p = strtok_r(s, " \t\r\n", &r); p != NULL;
	     p = strtok_r(NULL, " \t\r\n", &r))
		hash_set(cfg->co_classes, p, HASH_PRESENT);
	free(s);
}

k8s_config_t *
k8s_config_new(void)
{
k8s_config_t	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		TSError("calloc: %s", strerror(errno));
		return NULL;
	}

	ret->co_tls = 1;
	ret->co_remap = 1;
	ret->co_xfp = 1;
	ret->co_tls_verify = 1;

	cfg_set_ingress_classes(ret, "trafficserver");
	return ret;
}

k8s_config_t *
k8s_config_load(const char *file)
{
char		 line[1024], *s;
FILE		*f = NULL;
k8s_config_t	*ret = NULL;
int		 lineno = 0;

	if ((ret = k8s_config_new()) == NULL)
		return NULL;

	/*
	 * Check for in-cluster service account config.
	 */
	if ((f = fopen(SA_TOKEN_FILE, "r")) != NULL) {
		if (fgets(line, sizeof(line), f) != NULL) {
		char	*host, *port;

			while (strchr("\r\n", line[strlen(line) - 1]))
				line[strlen(line) - 1] = '\0';

			ret->co_token = strdup(line);

			host = getenv("KUBERNETES_SERVICE_HOST");
			port = getenv("KUBERNETES_SERVICE_PORT");

			if (host && port) {
			char	 buf[256];
				snprintf(buf, sizeof(buf), "https://%s:%s",
					 host, port);
				ret->co_server = strdup(buf);
			}
		}

		fclose(f);
		f = NULL;
	}

	if (file == NULL)
		return ret;

	if ((f = fopen(file, "r")) == NULL) {
		TSError("%s: %s", file, strerror(errno));
		goto error;
	}

	while (fgets(line, sizeof(line), f)) {
	char	*opt = line, *value = NULL, *s = line + strlen(line);

		++lineno;

		while (s >= line && strchr("\r\n", *s))
			*s-- = '\0';

		while (isspace(*opt))
			opt++;

		if (*opt == '#' || *opt == '\0')
			continue;

		if ((value = strchr(opt, ':')) == NULL) {
			TSError("%s:%d: syntax error", file, lineno);
			goto error;
		}

		*value++ = '\0';
		while (isspace(*value))
			value++;

		if (strcmp(opt, "server") == 0) {
			free(ret->co_server);
			ret->co_server = strdup(value);
		} else if (strcmp(opt, "token") == 0) {
			free(ret->co_token);
			ret->co_token = strdup(value);
		} else if (strcmp(opt, "certfile") == 0) {
			free(ret->co_tls_certfile);
			ret->co_tls_certfile = strdup(value);
		} else if (strcmp(opt, "keyfile") == 0) {
			free(ret->co_tls_keyfile);
			ret->co_tls_keyfile = strdup(value);
		} else if (strcmp(opt, "cafile") == 0) {
			free(ret->co_tls_cafile);
			ret->co_tls_cafile = strdup(value);
		} else if (strcmp(opt, "tls") == 0) {
			if (strcmp(value, "true") == 0)
				ret->co_tls = 1;
			else if (strcmp(value, "false") == 0)
				ret->co_tls = 0;
			else {
				TSError("%s:%d: expected \"true\" or \"false\"",
					file, lineno);
				goto error;
			}
		} else if (strcmp(opt, "tls_verify") == 0) {
			if (strcmp(value, "true") == 0)
				ret->co_tls_verify = 1;
			else if (strcmp(value, "false") == 0)
				ret->co_tls_verify = 0;
			else {
				TSError("%s:%d: expected \"true\" or \"false\"",
					file, lineno);
				goto error;
			}
		} else if (strcmp(opt, "remap") == 0) {
			if (strcmp(value, "true") == 0)
				ret->co_remap = 1;
			else if (strcmp(value, "false") == 0)
				ret->co_remap = 0;
			else {
				TSError("%s:%d: expected \"true\" or \"false\"",
					file, lineno);
				goto error;
			}
		} else if (strcmp(opt, "x_forwarded_proto") == 0) {
			if (strcmp(value, "true") == 0)
				ret->co_xfp = 1;
			else if (strcmp(value, "false") == 0)
				ret->co_xfp = 0;
			else {
				TSError("%s:%d: expected \"true\" or \"false\"",
					file, lineno);
				goto error;
			}
		} else if (strcmp(opt, "ingress_classes") == 0) {
			cfg_set_ingress_classes(ret, value);
		} else {
			TSError("%s:%d: unknown option \"%s\"",
				file, lineno, opt);
			goto error;
		}
	}

	if ((s = getenv("TS_SERVER")) != NULL) {
		free(ret->co_server);
		ret->co_server = strdup(s);
	}

	if ((s = getenv("TS_CAFILE")) != NULL) {
		free(ret->co_tls_cafile);
		ret->co_tls_cafile = strdup(s);
	}

	if ((s = getenv("TS_CERTFILE")) != NULL) {
		free(ret->co_tls_certfile);
		ret->co_tls_certfile = strdup(s);
	}

	if ((s = getenv("TS_KEYFILE")) != NULL) {
		free(ret->co_tls_keyfile);
		ret->co_tls_keyfile = strdup(s);
	}

	if ((s = getenv("TS_TOKEN")) != NULL) {
		free(ret->co_token);
		ret->co_token = strdup(s);
	}

	if ((s = getenv("TS_TLS")) != NULL) {
		if (strcmp(s, "true") == 0)
			ret->co_tls = 1;
		else if (strcmp(s, "false") == 0)
			ret->co_tls = 0;
		else {
			TSError("$TS_TLS: expected \"true\" or \"false\","
				" not \"%s\"", s);
			goto error;
		}
	}

	if ((s = getenv("TS_TLS_VERIFY")) != NULL) {
		if (strcmp(s, "true") == 0)
			ret->co_tls_verify = 1;
		else if (strcmp(s, "false") == 0)
			ret->co_tls_verify = 0;
		else {
			TSError("$TS_TLS_VERIFY: expected \"true\" or \"false\","
				" not \"%s\"", s);
			goto error;
		}
	}

	if ((s = getenv("TS_REMAP")) != NULL) {
		if (strcmp(s, "true") == 0)
			ret->co_remap = 1;
		else if (strcmp(s, "false") == 0)
			ret->co_remap = 0;
		else {
			TSError("$TS_REMAP: expected \"true\" or \"false\","
				" not \"%s\"", s);
			goto error;
		}
	}

	if ((s = getenv("TS_INGRESS_CLASSES")) != NULL)
		cfg_set_ingress_classes(ret, s);

	if (ret->co_tls_keyfile) {
		free(ret->co_token);
		ret->co_token = NULL;
	}

	if (ret->co_tls_keyfile && !ret->co_tls_certfile) {
		TSError("%s: must specify certfile with keyfile", file);
		goto error;
	}

	if (ret->co_tls_certfile && !ret->co_tls_keyfile) {
		TSError("%s: must specify keyfile with certfile", file);
		goto error;
	}

	if (!ret->co_server) {
		TSError("%s: must specify server", file);
		goto error;
	}

	return ret;
error:
	if (f)
		fclose(f);
	k8s_config_free(ret);
	return NULL;
}
