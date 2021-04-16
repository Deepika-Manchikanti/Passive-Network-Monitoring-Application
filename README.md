# Passive-Network-Monitoring-Application
Application designed to sniff traffic from the network

mydump - A simplified version of tcpdump
-------------------------------------------------------------------------------

mydump.go

- A Passive Network Monitoring Application written in Go using the GoPacket library.
- Captures the traffic from a network interface in promiscuous mode (or reads the packets from a pcap trace file).
- Prints a record for each packet in its standard output.
(Standard Output - A record containing the timestamp, source and destination MAC addresses, EtherType (as a hexadecimal number), packet length, source and destination IP addresses, protocol type (supports only "TCP", "UDP", "ICMP", and "OTHER"), source and destination ports (for TCP and UDP packets), the TCP flags in case of TCP packets, and the raw content of the packet payload.)
- Supports the following protocols:
	1.	Link Layer: Ethernet
	2.	Network Layer: IP
	3.	Transport Layer: TCP, UDP, ICMP
Prints "OTHER" for all protocol types
- Supports a BPF filter for capturing a subset of the traffic.
- Supports a string pattern for capturing only packets with matching payloads. 

Arguments supported : 

go run mydump.go [-i interface] [-r file] [-s string] expression

-i  Live capture from the network device <interface> (e.g., eth0). If not specified, mydump will automatically select a default interface to listen on. Capturing continues indefinitely until the user terminates the program.

-r  Read packets from <file> in tcpdump format.

-s  Keep only packets that contain <string> in their payload (after any BPF filter is applied) implementing a string matching operation.

<expression> -  a BPF filter that specifies which packets will be dumped. If no filter is given, all packets seen on the interface (or contained in the trace) will be dumped. Otherwise, only packets matching <expression> will be dumped.

Application flow:

- Required packages were imported and global variables were declared.
- pcap.FindAllDevs() function finds all devices connected to the network.
- Then fileFlag, interf and strPattern variables have been used to get command line arguments specified by the user (file, interface and string expression respectively).
- pcap.OpenOffline() function reads packets from <file>(pcap file) in tcpdump format.
- pcap.OpenLive() function opens device for live capture(sniffing) in promiscuous mode.
- If both interface and pcap file are specified, mydump reads from the pcap file.
- If both interface and pcap file aren’t specified, mydump finds a default device (en0 on macOS) on which to capture.
- Setting a BPF filter expression specified by the user to filter a subset of traffic.
- Checking if packet is an ethernet packet.
- Checking for <string> pattern in the payload, to capture only packets with matching payload.
- Checking if packet is IP.
- Checking if packet is TCP.
- Checking if packet is UDP.
- Checking for errors.
- Printing in standard output format.

Example output:
 
1)Executing mydump.go without any interface or pcap file specification - reads from en0.
Command : go run mydump.go

Reading from interface  en0
2021-03-12 22:34:30.4289 -0500 EST 18:3e:ef:f2:31:7e -> aa:bb:cc:dd:ee:ff type 0x800 len 66 172.24.18.236 : 61267 -> 68.67.160.117 : 443 TCP ACK 00000000  45 00 00 34 00 00 40 00  40 06 97 07 ac 18 12 ec  |E..4..@.@.......|
00000010  44 43 a0 75 ef 53 01 bb  f8 ae e5 13 ba c1 32 6f  |DC.u.S........2o|
00000020  80 10 07 af 41 62 00 00  01 01 08 0a 47 a3 dd c5  |....Ab......G...|
00000030  1d d7 8a ac                                       |....|
 
2)To Obtain packets with pcap file specified
Command : go run my dump.go -r “hw1.pcap”

Reading from file hw1.pcap
2013-01-12 12:10:10.384243 -0500 EST c4:3d:c7:17:6f:9b -> ff:ff:ff:ff:ff:ff type 0x806 len 60  OTHER  00000000  00 01 08 00 06 04 00 01  c4 3d c7 17 6f 9b c0 a8  |.........=..o...|
00000010  00 01 00 00 00 00 00 00  c0 a8 00 06 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00        |..............|

3)To Obtain packets with interface specified
Command : go run my dump.go -i en0

Reading from interface  en0
2021-03-12 22:36:37.907362 -0500 EST 08:f1:ea:5e:4a:00 -> 18:3e:ef:f2:31:7e type 0x800 len 97 137.116.89.182 : 443 -> 172.24.18.236 : 61335 TCP ACKPSH 00000000  45 00 00 53 41 98 40 00  31 06 65 de 89 74 59 b6  |E..SA.@.1.e..tY.|
00000010  ac 18 12 ec 01 bb ef 97  46 19 40 fc e9 40 9a 21  |........F.@..@.!|
00000020  80 18 01 f5 ae 22 00 00  01 01 08 0a 4f bc 56 d1  |....."......O.V.|
00000030  47 a5 b9 cb 15 03 03 00  1a c7 68 fe eb 04 10 e7  |G.........h.....|
00000040  67 1e 73 db 12 a7 dd b7  30 00 63 fb 61 88 b9 e8  |g.s.....0.c.a...|
00000050  51 0c 1d                                          |Q..|

4)To Obtain packets with the string “Broadcom” in payload
Command : go run mudump.go -r “hw1.pcap” -s “Broadcom”

2013-01-12 16:06:44.026093 -0500 EST c4:3d:c7:17:6f:9b -> 01:00:5e:7f:ff:fa type 0x800 len 340 192.168.0.1 : 1900 -> 239.255.255.250 : 1900 UDP  00000000  45 00 01 46 03 da 00 00  01 11 04 2a c0 a8 00 01  |E..F.......*....|
00000010  ef ff ff fa 07 6c 07 6c  01 32 dc 59 4e 4f 54 49  |.....l.l.2.YNOTI|
00000020  46 59 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |FY * HTTP/1.1..H|
00000030  6f 73 74 3a 20 32 33 39  2e 32 35 35 2e 32 35 35  |ost: 239.255.255|
00000040  2e 32 35 30 3a 31 39 30  30 0d 0a 43 61 63 68 65  |.250:1900..Cache|
00000050  2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67  |-Control: max-ag|
00000060  65 3d 36 30 0d 0a 4c 6f  63 61 74 69 6f 6e 3a 20  |e=60..Location: |
00000070  68 74 74 70 3a 2f 2f 31  39 32 2e 31 36 38 2e 30  |http://192.168.0|
00000080  2e 31 3a 31 39 30 30 2f  57 46 41 44 65 76 69 63  |.1:1900/WFADevic|
00000090  65 2e 78 6d 6c 0d 0a 4e  54 53 3a 20 73 73 64 70  |e.xml..NTS: ssdp|
000000a0  3a 61 6c 69 76 65 0d 0a  53 65 72 76 65 72 3a 20  |:alive..Server: |
000000b0  50 4f 53 49 58 2c 20 55  50 6e 50 2f 31 2e 30 20  |POSIX, UPnP/1.0 |
000000c0  42 72 6f 61 64 63 6f 6d  20 55 50 6e 50 20 53 74  |Broadcom UPnP St|
000000d0  61 63 6b 2f 65 73 74 69  6d 61 74 69 6f 6e 20 31  |ack/estimation 1|
000000e0  2e 30 30 0d 0a 4e 54 3a  20 75 75 69 64 3a 46 35  |.00..NT: uuid:F5|
000000f0  31 39 33 39 30 41 2d 34  34 44 44 2d 32 39 35 38  |19390A-44DD-2958|
00000100  2d 36 32 33 37 2d 45 41  33 37 42 39 38 37 43 33  |-6237-EA37B987C3|
00000110  46 44 0d 0a 55 53 4e 3a  20 75 75 69 64 3a 46 35  |FD..USN: uuid:F5|
00000120  31 39 33 39 30 41 2d 34  34 44 44 2d 32 39 35 38  |19390A-44DD-2958|
00000130  2d 36 32 33 37 2d 45 41  33 37 42 39 38 37 43 33  |-6237-EA37B987C3|
00000140  46 44 0d 0a 0d 0a                                 |FD....|

5)To Obtain packets with tcp SYN flag
Command : go run hello.go -r "hw1.pcap" "tcp[tcpflags] == tcp-syn" 

2013-01-14 12:48:18.471308 -0500 EST c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 74 1.234.31.20 : 55672 -> 192.168.0.200 : 80 TCP SYN 00000000  45 00 00 3c fb b8 40 00  2f 06 6d 95 01 ea 1f 14  |E..<..@./.m.....|
00000010  c0 a8 00 c8 d9 78 00 50  0c 2a 90 61 00 00 00 00  |.....x.P.*.a....|
00000020  a0 02 39 08 bf 45 00 00  02 04 05 b4 04 02 08 0a  |..9..E..........|
00000030  8b 16 6b d9 00 00 00 00  01 03 03 07              |..k.........|
