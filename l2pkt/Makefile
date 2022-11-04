PROG=	l2pkt
SRCS=	l2pkt.c toeplitz_hash.c
MKPIE=	no

CFLAGS+=	-I../libl2pkt
LDADD+=		../libl2pkt/libl2pkt.a

MK_MAN=	no
NOMAN=	yes

.include <bsd.prog.mk>
