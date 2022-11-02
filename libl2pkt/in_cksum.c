/*-
 * Copyright (c) 2008 Joerg Sonnenberger <joerg@NetBSD.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include "libl2pkt.h"
#include "dummy_mbuf.h"

unsigned int
in4_cksum(struct in_addr src, struct in_addr dst, int proto, char *data, unsigned int len)
{
	uint32_t sum;

	sum = (src.s_addr >> 16) & 0xffff;
	sum += src.s_addr & 0xffff;
	sum += (dst.s_addr >> 16) & 0xffff;
	sum += dst.s_addr & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum += (proto << 8);
	sum += htons(len);
#else
	sum += proto;
	sum += len;
#endif

	return in_cksum(sum, data, len);
}

unsigned int
in6_cksum(struct in6_addr *src, struct in6_addr *dst, int proto, char *data, unsigned int len)
{
	uint32_t sum;

#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif

	sum = src->s6_addr16[0];
	sum += src->s6_addr16[1];
	sum += src->s6_addr16[2];
	sum += src->s6_addr16[3];
	sum += src->s6_addr16[4];
	sum += src->s6_addr16[5];
	sum += src->s6_addr16[6];
	sum += src->s6_addr16[7];

	sum += dst->s6_addr16[0];
	sum += dst->s6_addr16[1];
	sum += dst->s6_addr16[2];
	sum += dst->s6_addr16[3];
	sum += dst->s6_addr16[4];
	sum += dst->s6_addr16[5];
	sum += dst->s6_addr16[6];
	sum += dst->s6_addr16[7];
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum += (proto << 8);
	sum += htons(len);
#else
	sum += proto;
	sum += len;
#endif

	return in_cksum(sum, data, len);
}

#ifdef __x86_64__
int cpu_in_cksum(void *, int, int, uint32_t);

unsigned int
in_cksum(unsigned int sum0, char *data, unsigned int len)
{
	struct dummy_mbuf dummy_mbuf;

	dummy_mbuf.m_next = NULL;
	dummy_mbuf.m_data = data;
	dummy_mbuf.m_len = len;

	return cpu_in_cksum(&dummy_mbuf, len, 0, sum0);
}
#else /* __x86_64__ */
unsigned int
in_cksum(unsigned int sum, char *data, unsigned int len)
{
	if ((uintptr_t)data & 1) {
#if _BYTE_ORDER == _LITTLE_ENDIAN
		sum += *(uint8_t *)data++ << 8;
#else
		sum += *(uint8_t *)data++;
#endif
		len--;
	}

	while (len >= 2) {
		sum += *(uint16_t *)data;
		data += 2;
		len -= 2;
	}

	if (len & 1) {
#if _BYTE_ORDER == _LITTLE_ENDIAN
		sum += *(uint8_t *)data++;
#else
		sum += *(uint8_t *)data++ << 8;
#endif
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return ~(sum & 0xffff);
}
#endif /* __x86_64__ */
