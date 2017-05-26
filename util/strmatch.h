/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef STRMATCH_H
#define STRMATCH_H

#ifdef __cplusplus
extern "C" {
#endif

int strmatch(const char *str, const char *strend,
             const char *pat, const char *patend);

#ifdef __cplusplus
}
#endif

#endif  /* !STRMATCH_H */
