/*
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "libl2pkt.h"

#include <string.h>

#ifdef __NetBSD__
#include <net/if_ether.h>
#elif defined(__OpenBSD__)
#include <netinet/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#define ether_addr_octet octet
#endif

int
l2pkt_ethpkt_template(struct l2pkt *l2pkt)
{
	struct ether_header *eh;

	eh = (struct ether_header *)L2PKT_BUFFER(l2pkt);

	memset(eh->ether_shost, 0x00, ETHER_ADDR_LEN);
	memset(eh->ether_dhost, 0xff, ETHER_ADDR_LEN);
	eh->ether_type = htons(ETHERTYPE_IP);

	return 0;
}

int
l2pkt_ethpkt_type(struct l2pkt *l2pkt, uint16_t type)
{
	struct ether_header *eh;

	eh = (struct ether_header *)L2PKT_BUFFER(l2pkt);
	eh->ether_type = htons(type);
	return 0;
}

int
l2pkt_ethpkt_src(struct l2pkt *l2pkt, struct ether_addr *eaddr)
{
	struct ether_header *eh;

	eh = (struct ether_header *)L2PKT_BUFFER(l2pkt);
	memcpy(eh->ether_shost, eaddr->ether_addr_octet, ETHER_ADDR_LEN);
	return 0;
}

int
l2pkt_ethpkt_dst(struct l2pkt *l2pkt, struct ether_addr *eaddr)
{
	struct ether_header *eh;

	eh = (struct ether_header *)L2PKT_BUFFER(l2pkt);
	memcpy(eh->ether_dhost, eaddr->ether_addr_octet, ETHER_ADDR_LEN);
	return 0;
}
