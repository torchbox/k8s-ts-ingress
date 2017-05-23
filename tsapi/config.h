/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	CONFIG_H
#define	CONFIG_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Service account credential files.
 */
#define SA_TOKEN_FILE	"/var/run/secrets/kubernetes.io/serviceaccount/token"
#define SA_CACERT_FILE	"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

typedef struct k8s_config {
	char	*co_host;
	int	 co_port;
	char	*co_tls_certfile;
	char	*co_tls_keyfile;
	char	*co_tls_cafile;
	char	*co_token;
	int	 co_tls;
	int	 co_remap;
} k8s_config_t;

k8s_config_t	*k8s_config_load(const char *file);
k8s_config_t	*k8s_incluster_config(void);
void		 k8s_config_free(k8s_config_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* !CONFIG_H */
