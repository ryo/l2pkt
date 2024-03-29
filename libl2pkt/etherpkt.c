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
l2pkt_ethpkt_encap_vlan(struct l2pkt *l2pkt, uint16_t encap_proto, uint16_t tag)
{
	struct ether_vlan_header *evl;
	char *p;

	p = L2PKT_BUFFER(l2pkt);
	memmove(
	    p + ETHER_ADDR_LEN * 2 + 4,
	    p + ETHER_ADDR_LEN * 2,
	    sizeof(L2PKT_BUFFER(l2pkt)) - 4);

	evl = (struct ether_vlan_header *)L2PKT_BUFFER(l2pkt);
	evl->evl_encap_proto = htons(encap_proto);
	evl->evl_tag = htons(tag);

	L2PKT_L2HEADERSIZE(l2pkt) += 4;
	L2PKT_L2SIZE(l2pkt) += 4;

	return 0;
}

int
l2pkt_ethpkt_encap_llc_snap(struct l2pkt *l2pkt)
{
	struct ether_header *eh;
	struct llc *llc;
	char *p;

	p = L2PKT_BUFFER(l2pkt);
	memmove(
	    p + ETHER_ADDR_LEN * 2 + 8,
	    p + ETHER_ADDR_LEN * 2,
	    sizeof(L2PKT_BUFFER(l2pkt)) - 8);

	eh = (struct ether_header *)L2PKT_BUFFER(l2pkt);

	llc = (struct llc *)(eh + 1);
	llc->llc_dsap = LLC_SNAP_LSAP;
	llc->llc_ssap = LLC_SNAP_LSAP;
	llc->llc_control = LLC_UI;
	llc->llc_un.type_snap.org_code[0] = 0;
	llc->llc_un.type_snap.org_code[1] = 0;
	llc->llc_un.type_snap.org_code[2] = 0;
	llc->llc_un.type_snap.ether_type = eh->ether_type;

	eh->ether_type = htons(L2PKT_L2SIZE(l2pkt) - 6);

	L2PKT_L2HEADERSIZE(l2pkt) += 8;
	L2PKT_L2SIZE(l2pkt) += 8;

	return 0;
}


int
l2pkt_ethpkt_type(struct l2pkt *l2pkt, uint16_t type)
{
	struct ether_vlan_header *evl;
	struct ether_header *eh;

	eh = (struct ether_header *)L2PKT_BUFFER(l2pkt);
	if (eh->ether_type == htons(ETHERTYPE_VLAN)) {
		evl = (struct ether_vlan_header *)eh;
		evl->evl_proto = htons(type);
	} else {
		eh->ether_type = htons(type);
	}
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
