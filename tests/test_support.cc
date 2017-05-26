/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<string>
#include	<iostream>
#include	<fstream>
#include	<iterator>

#include	<json.h>

#include	"tests/test.h"

json_object *
test_load_json(std::string const& fname)
{
	std::ifstream inf(fname);

	if (!inf)
		return nullptr;

	std::string json_str(std::istreambuf_iterator<char>{inf}, {});
	json_object *obj = json_tokener_parse(json_str.c_str());
	return obj;
}
