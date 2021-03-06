/*-
 * Copyright (c) 2019 Ryo Shimizu <ryo@nerv.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>
#include <stddef.h>
#include <stdarg.h>

#include "toeplitz_hash.h"

uint8_t rsskey[RSSKEY_SIZE] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

/*
 * e.g.)
 *
 * struct in_addr src, dst;
 * toeplitz_vhash(rsskey[], sizeof(rsskey),
 *                   &src, sizeof(src),
 *                   &dst, sizeof(dst),
 *                   NULL);
 *
 * struct in6_addr src6, dst6;
 * toeplitz_vhash(rsskey[], sizeof(rsskey),
 *                   &src6, sizeof(src6),
 *                   &dst6, sizeof(dst6),
 *                   NULL);
 *
 * struct ip *ip;
 * struct tcphdr *tcp;
 * toeplitz_vhash(rsskey[], sizeof(rsskey),
 *                   &ip->ip_src, sizeof(ip->ip_src),
 *                   &ip->ip_dst, sizeof(ip->ip_dst),
 *                   &tcp->th_sport, sizeof(tcp->th_sport),
 *                   &tcp->th_dport, sizeof(tcp->th_dport),
 *                   NULL);
 *
 */
uint32_t
toeplitz_vhash(const uint8_t *keyp, size_t keylen, ...)
{
	va_list ap;
	uint32_t hash, v;
	size_t datalen;
	uint8_t *datap, key, data;
	const uint8_t *keyend;

	keyend = keyp + keylen;

	/* first 32bit is initial vector */
	v = *keyp++;
	v <<= 8;
	v |= *keyp++;
	v <<= 8;
	v |= *keyp++;
	v <<= 8;
	v |= *keyp++;

	hash = 0;
	va_start(ap, keylen);

	while ((datap = va_arg(ap, uint8_t *)) != NULL) {
		for (datalen = va_arg(ap, size_t); datalen > 0; datalen--) {
			/* fetch key and input data by 8bit */
			if (keyp < keyend)
				key = *keyp++;
			else
				key = 0;
			data = *datap++;

#define XOR_AND_FETCH_BIT(x)			\
			if (data & __BIT(x))		\
				hash ^= v;		\
			v <<= 1;			\
			if (key & __BIT(x))		\
				v |= 1;

			XOR_AND_FETCH_BIT(7);
			XOR_AND_FETCH_BIT(6);
			XOR_AND_FETCH_BIT(5);
			XOR_AND_FETCH_BIT(4);
			XOR_AND_FETCH_BIT(3);
			XOR_AND_FETCH_BIT(2);
			XOR_AND_FETCH_BIT(1);
			XOR_AND_FETCH_BIT(0);

#undef XOR_AND_FETCH_BIT
		}
	}
	va_end(ap);

	return hash;
}
