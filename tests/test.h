/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef TEST_H
#define TEST_H

#ifdef __cplusplus
extern "C" {
#endif

extern int ts_api_errors;

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include	<json.h>
#include	<string>

json_object *test_load_json(std::string const& fname);

template<typename T>
struct scoped_c_ptr {
	typedef void (*free_fn_t) (T);

	scoped_c_ptr(T ptr, free_fn_t fn) : ptr(ptr), free_fn(fn) {}

	~scoped_c_ptr() {
		free_fn(ptr);
	}

	T ptr;
	free_fn_t free_fn;
};
#endif

#endif  /* !TEST_H */
