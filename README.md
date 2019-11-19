# l2pkt - build L2-L4 test packet

## example
~~~
# l2pkt -i wm0 -f 128 -S 1:2:3:4:5:6 -D a:b:c:d:e:f -4 --proto tcp --src 10.0.0.0 --dst 10.1.0.1 --ip4csum 0xDEAD --l4csum 0xBEEF --rsshash2 0xdead/0x10000 --rsshash4 0xbeef/0x10000 -X -v
Found rsshash2(10.0.133.110,10.1.0.1): 0x746adead % 0x00010000 == 0x0000dead    
Found rsshash4(10.0.133.110,10.1.0.1,1993,3): 0x0a4ebeef % 0x00010000 == 0x0000beef         
Protocol tcp(6), 10.0.133.110:1993 -> 10.1.0.1:3
RssHash(2-tuple): 0x746adead
RssHash(4-tuple): 0x0a4ebeef

framesize:  128 bytes
packetsize: 114 bytes
L2 framesize = 128, L3 packetsize = 114
01:02:03:04:05:06 -> 0a:0b:0c:0d:0e:0f, ethertype 0x0800
00000000: 45 00 00 72 42 69 00 00 00 06 de ad 0a 00 85 6e <E..rBi.........n>
00000010: 0a 01 00 01 07 c9 00 03 00 00 00 00 00 00 00 00 <................>
00000020: 50 00 00 00 be ef 00 00 00 00 00 00 00 00 00 00 <P...............>
00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <................>
00000040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <................>
00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <................>
00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <................>
00000070: 4f 6f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <Oo..............>
00000080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <................>
00000090: 00 00                                           <..>
writing 128 bytes
~~~
