/*
 * Copyright (c) 2015 Ryo Shimizu <ryo@nerv.org>
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/if_ether.h>

struct tcpdump_hdr {
	uint32_t byteorder_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint32_t section_length;
	uint16_t linktype;
	uint16_t reserved;
	uint32_t snaplen;

	uint16_t interface_id;
	uint16_t drop_count;
};

struct tcpdump_pkthdr {
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t capture_len;
	uint32_t packet_len;
};

int
tcpdumpfile_open(const char *name)
{
	struct tcpdump_hdr thdr;
	int fd;

	if ((name == NULL) || (strcmp(name, "-") == 0))
		fd = STDOUT_FILENO;
	else
		fd = open(name, O_WRONLY|O_CREAT|O_TRUNC, 0666);

	if (fd >= 0) {
		memset(&thdr, 0, sizeof(thdr));
		thdr.byteorder_magic = 0xa1b2c3d4;
		thdr.major_version = 2;
		thdr.minor_version = 4;
		thdr.snaplen = 65535;

		thdr.interface_id = 1;
		thdr.drop_count = 0;

		write(fd, &thdr, sizeof(thdr));
	}

	return fd;
}

ssize_t
tcpdumpfile_output(int fd, char *buf, int len)
{
	struct tcpdump_pkthdr tphdr;
	struct timeval tv;
	struct iovec iov[2];

	memset(&tphdr, 0, sizeof(tphdr));

	gettimeofday(&tv, NULL);
	tphdr.timestamp_high = tv.tv_sec;
	tphdr.timestamp_low = tv.tv_usec;
	tphdr.capture_len = len;
	tphdr.packet_len = len;

	iov[0].iov_base = &tphdr;
	iov[0].iov_len = sizeof(tphdr);
	iov[1].iov_base = buf;
	iov[1].iov_len = len;
	return writev(fd, iov, 2);
}

void
tcpdumpfile_close(int fd)
{
	close(fd);
}

#ifdef STANDALONE_TEST
int
main(int argc, char *argv[])
{
	int fd;

	fd = tcpdumpfile_open("xxx");
	tcpdumpfile_output(fd, "0XXXXXXXXXXXXXFXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 61);
	tcpdumpfile_output(fd, "0AAAAAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 62);
	tcpdumpfile_output(fd, "0BBBBBBBBBBBBBFBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 63);
	tcpdumpfile_output(fd, "0CCCCCCCCCCCCCFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 64);
	tcpdumpfile_close(fd);
}
#endif

