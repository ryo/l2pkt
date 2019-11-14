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

#ifdef USE_CPU_IN_CKSUM
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
#else /* USE_CPU_IN_CKSUM */
unsigned int
in_cksum(unsigned int sum0, char *data, unsigned int len)
{
	uint64_t sum, partial;
	unsigned int final_acc;
	int needs_swap, started_on_odd;

	needs_swap = 0;
	started_on_odd = 0;
	sum = sum0;

	partial = 0;
	if ((uintptr_t)data & 1) {
		/* Align on word boundary */
		started_on_odd = !started_on_odd;
#if _BYTE_ORDER == _LITTLE_ENDIAN
		partial = *data << 8;
#else
		partial = *data;
#endif
		++data;
		--len;
	}
	needs_swap = started_on_odd;
	if ((uintptr_t)data & 2) {
		if (len < 2)
			goto trailing_bytes;
		partial += *(uint16_t *)data;
		data += 2;
		len -= 2;
	}
	while (len >= 64) {
		__builtin_prefetch(data + 32);
		__builtin_prefetch(data + 64);
		partial += *(uint32_t *)data;
		partial += *(uint32_t *)(data + 4);
		partial += *(uint32_t *)(data + 8);
		partial += *(uint32_t *)(data + 12);
		partial += *(uint32_t *)(data + 16);
		partial += *(uint32_t *)(data + 20);
		partial += *(uint32_t *)(data + 24);
		partial += *(uint32_t *)(data + 28);
		partial += *(uint32_t *)(data + 32);
		partial += *(uint32_t *)(data + 36);
		partial += *(uint32_t *)(data + 40);
		partial += *(uint32_t *)(data + 44);
		partial += *(uint32_t *)(data + 48);
		partial += *(uint32_t *)(data + 52);
		partial += *(uint32_t *)(data + 56);
		partial += *(uint32_t *)(data + 60);
		data += 64;
		len -= 64;
		if (__predict_false(partial & (3ULL << 62))) {
			if (needs_swap)
				partial = (partial << 8) + (partial >> 56);
			sum += (partial >> 32);
			sum += (partial & 0xffffffff);
			partial = 0;
		}
	}
	/*
	 * len is not updated below as the remaining tests
	 * are using bit masks, which are not affected.
	 */
	if (len & 32) {
		partial += *(uint32_t *)data;
		partial += *(uint32_t *)(data + 4);
		partial += *(uint32_t *)(data + 8);
		partial += *(uint32_t *)(data + 12);
		partial += *(uint32_t *)(data + 16);
		partial += *(uint32_t *)(data + 20);
		partial += *(uint32_t *)(data + 24);
		partial += *(uint32_t *)(data + 28);
		data += 32;
	}
	if (len & 16) {
		partial += *(uint32_t *)data;
		partial += *(uint32_t *)(data + 4);
		partial += *(uint32_t *)(data + 8);
		partial += *(uint32_t *)(data + 12);
		data += 16;
	}
	if (len & 8) {
		partial += *(uint32_t *)data;
		partial += *(uint32_t *)(data + 4);
		data += 8;
	}
	if (len & 4) {
		partial += *(uint32_t *)data;
		data += 4;
	}
	if (len & 2) {
		partial += *(uint16_t *)data;
		data += 2;
	}
 trailing_bytes:
	if (len & 1) {
#if _BYTE_ORDER == _LITTLE_ENDIAN
		partial += *data;
#else
		partial += *data << 8;
#endif
		started_on_odd = !started_on_odd;
	}

	if (needs_swap)
		partial = (partial << 8) + (partial >> 56);
	sum += (partial >> 32) + (partial & 0xffffffff);
	/*
	 * Reduce sum to allow potential byte swap
	 * in the next iteration without carry.
	 */
	sum = (sum >> 32) + (sum & 0xffffffff);

	final_acc = (sum >> 48) + ((sum >> 32) & 0xffff) +
	    ((sum >> 16) & 0xffff) + (sum & 0xffff);
	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	return ~final_acc & 0xffff;
}
#endif /* USE_CPU_IN_CKSUM */
