CFLAGS+=	-Wall
LIB=	l2pkt
INTERNALLIB=

SRCS+=	l2pkt.c
SRCS+=	etherpkt.c
SRCS+=	ip4pkt.c
SRCS+=	ip6pkt.c
SRCS+=	l4pkt.c
SRCS+=	utils.c
SRCS+=	tcpdumpfile.c

# x86_64
#CFLAGS+=-DUSE_CPU_IN_CKSUM

SRCS+=	in_cksum.c
SRCS+=	cpu_in_cksum.S

.include <bsd.lib.mk>
