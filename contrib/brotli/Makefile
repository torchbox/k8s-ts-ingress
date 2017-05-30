# vim:set sw=8 ts=8 noet:
#
# Copyright (c) 2016-2017 Torchbox Ltd.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely. This software is provided 'as-is', without any express or implied
# warranty.

VPATH=	common enc
SRCS=	backward_references.c backward_references_hq.c bit_cost.c	\
        block_splitter.c brotli_bit_stream.c cluster.c			\
	compress_fragment.c compress_fragment_two_pass.c dictionary.c	\
	dictionary_hash.c encode.c entropy_encode.c histogram.c		\
	literal_cost.c memory.c metablock.c static_dict.c utf8_util.c
OBJS=	${SRCS:.c=.o}

CC=		clang-4.0
CXX=		clang++-4.0
CPPFLAGS=	 -Iinclude
CFLAGS=		-O0 -g3 -ggdb -std=gnu99 -g -pipe -Wall -Wno-deprecated-declarations -Qunused-arguments -Wextra -Wno-ignored-qualifiers -Wno-unused-parameter -fno-strict-aliasing -fno-omit-frame-pointer -fsanitize=address -mcx16  -fPIC

libbrotli.a: ${OBJS}
	ar rcu libbrotli.a ${OBJS}

%.o: %.c
	${CC} ${CPPFLAGS} ${CFLAGS} -c $<
