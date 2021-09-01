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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_ether.h>

#include "libl2pkt.h"

static inline bool
iszero16(const char *data)
{
	int i;
	for (i = 0; i < 16; i++) {
		if (data[i] != 0)
			return false;
	}
	return true;
}

int
fdumpstr(FILE *fp, const char *data, size_t len, bool abbrev_zero)
{
	char ascii[17];
	size_t i;
	unsigned int lastzero = 0;

	ascii[16] = '\0';
	for (i = 0; i < len; i++) {
		unsigned char c;

		if ((i & 15) == 0) {
			if (abbrev_zero) {
				if ((len - i) >= 16) {
					if (iszero16(&data[i])) {
						if (lastzero) {
							if (lastzero == 1)
								fprintf(fp, "*\n");
							lastzero++;
							i += 15;
							continue;
						}
						lastzero = 1;
					} else {
						lastzero = 0;
					}
				}
			}
			fprintf(fp, "%08x:", (unsigned int)i);
		}

		if ((i & 15) == 8)
			fprintf(fp, " ");

		c = data[i];
		fprintf(fp, " %02x", c);

		ascii[i & 15] = (0x20 <= c && c <= 0x7e) ? c : '.';

		if ((i & 15) == 15)
			fprintf(fp, "  <%s>\n", ascii);
	}
	ascii[len & 15] = '\0';

	if (len & 15) {
		const char *white = "                                                ";
		fprintf(fp, "%s   <%s>\n", &white[(len & 15) * 3], ascii);
	}

	return 0;
}

int
dumpstr(const char *str, size_t len, bool abbrev_zero)
{
	return fdumpstr(stdout, str, len, abbrev_zero);
}

void
packetdump(const char *packet, size_t pktsize, bool abbrev)
{
	char buf[sizeof("00:00:00:00:00:00")];
	struct ether_header *eh;
	uint16_t etype;

	eh = (struct ether_header *)packet;
	etype = ntohs(eh->ether_type);
	strlcpy(buf, ether_ntoa((struct ether_addr *)eh->ether_shost), sizeof(buf));

	if (etype < ETHERMTU) {
		printf("%s -> %s, 802.3 length 0x%04x(%u)\n", buf, ether_ntoa((struct ether_addr *)eh->ether_dhost), etype, etype);
	} else {
		printf("%s -> %s, ethertype 0x%04x\n", buf, ether_ntoa((struct ether_addr *)eh->ether_dhost), etype);
	}
	dumpstr(packet + sizeof(struct ether_header), pktsize - sizeof(struct ether_header), abbrev);
}
