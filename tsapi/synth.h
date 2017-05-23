/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef SYNTH_H
#define SYNTH_H

#include	<stdarg.h>

#include	<ts/ts.h>

/*
 * Simple API for sending synthetic replies, used in various places.
 */

typedef struct synth synth_t;

synth_t	*synth_new(int status, const char *reason);
void 	 synth_free(synth_t *);
void 	 synth_add_header(synth_t *, const char *hdr, const char *fmt, ...);
void 	 synth_vadd_header(synth_t *, const char *hdr,
			   const char *fmt, va_list);
void 	 synth_set_body(synth_t *, const char *body);
void	 synth_intercept(synth_t *, TSHttpTxn);

#endif  /* !SYNTH_H */
