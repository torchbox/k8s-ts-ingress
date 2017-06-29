/*	vim:set sw=8 ts=8 noet: */
/*	$NetBSD: fnmatch.c,v 1.21 2005/12/24 21:11:16 perry Exp $	*/

/*
 * Copyright (c) 1989, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include	<ctype.h>
#include	<stdlib.h>

static char const	*strrangematch(char const *, char const *, int);

int
strmatch(const char *str, const char *strend,
	 const char *pattern, const char *patend)
{
char	c;
	for (;;) {
		if (pattern == patend) {
			if (str == strend)
				return 1;
			else
				return 0;
		}

		switch (c = tolower(*pattern++)) {
		case '?':
			if (str == strend)
				return 0;
			str++;
			break;

		case '*':
			if (pattern == patend)
				return 1;
			c = tolower(*pattern);

			while (c == '*')
				c = tolower(*++pattern);

			if (pattern == patend)
				return 1;

			while (str < strend) {
				if (strmatch(str, strend, pattern, patend))
					return 1;
				str++;
			}

		case '[':
			if (str == strend)
				return 0;
			if ((pattern = strrangematch(pattern, patend, tolower(*str))) == NULL)
				return 0;
			++str;
			break;

		case '\\':
			c = tolower(*pattern++);
			if (pattern == patend) {
				c = '\\';
				--pattern;
			}

		default:
			if (c != tolower(*str++))
				return 0;
			break;
		}
	}
}

static char const *
strrangematch(const char *pattern, const char *patend, int test)
{
int	negate, ok;
char	c, c2;

	/*
	 * A bracket expression starting with an unquoted circumflex
	 * character produces unspecified results (IEEE 1003.2-1992,
	 * 3.13.2).  This implementation treats it like '!', for
	 * consistency with the regular expression syntax.
	 * J.T. Conklin (conklin@ngai.kaleida.com)
	 */
	if ((negate = (*pattern == '!' || *pattern == '^')) != 0)
		++pattern;

	for (ok = 0; (c = tolower(*pattern++)) != ']';) {
		if (c == '\\')
			c = tolower(*pattern++);
		if (pattern == patend)
			return NULL;
		if (*pattern == '-') {
			c2 = tolower(*(pattern + 1));
			if (pattern != patend && c2 != ']')
				pattern += 2;
			if (c2 == '\\')
				c2 = tolower(*pattern++);
			if (pattern == patend)
				return NULL;
			if (c <= test && test <= c2)
				ok = 1;
		} else if (c == test)
			ok = 1;
	}

	return ok == negate ? NULL : pattern;
}
