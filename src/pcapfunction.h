#ifndef PCAPFUNCTION_H
#define PCAPFUNCTION_H

#include<pcap.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define zero(s)	memset(s, 0, sizeof(s))

char ifdev[10][10];
char select_dev[10];
char bpf_filter_str[100];
#define DUMPFILE "swordCapture.cap"	// 临时文件名
pcap_dumper_t *pcapfp;

/* packets number statistics */
uint arpn, icmpn, udpn, tcpn, ipn, alln;

int find_interfaces(int *n);

/*defined in pcapfunction.c, used in signalfunction.c */
void packet_capture();
/*
* packet header struct
*/
struct ether_header {
	u_int8_t dst_mac[6];
	u_int8_t src_mac[6];
	u_int16_t ether_type;
};

typedef u_int32_t in_addr_t;

//arp
struct arp_header {
	u_int16_t htype;
	u_int16_t ptype;
	u_int8_t hlen;
	u_int8_t plen;
	u_int16_t oper;
	u_int8_t sha[6];
	u_int8_t spa[4];
	u_int8_t tha[6];
	u_int8_t tpa[4];
};
//ipv4
struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t ip_hdr_len:4, ip_version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t ip_version:4, ip_hdr_len:4;
#else
#error	"Please fix <bits/endian.h>"
#endif
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t checksum;
	struct in_addr src_addr;
	struct in_addr dst_addr;
};
//ipv6
struct ipv6_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t traffic_class_1:4, ip_version:4;
	u_int8_t flow_label_1:4, traffic_class_2:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t ip_version:4, traffic_class_1:4;
	u_int8_t traffic_class_2:4, flow_label:4;
#else
#error	"Please fix <bits/endian.h>"
#endif
	u_int16_t flow_label_2;
	u_int16_t payload_length;
	u_int8_t next_header;
	u_int8_t hop_limit;

	u_char src_ipv6[16];
	u_char dst_ipv6[16];
};
//udp
struct udp_header {
	u_int16_t src_port;
	u_int16_t dst_port;
	u_int16_t len;
	u_int16_t checksum;
};
//tcp
struct tcp_header {
	u_int16_t src_port;	/* source port */
	u_int16_t dst_port;	/* destination port */
	u_int32_t tcp_seq;	/* sequence number */
	u_int32_t tcp_ack;	/* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t tcp_reserved:4,	/* (unused) */
	 tcp_off:4;		/* data offset */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t tcp_off:4, tcp_reserved:4;
#endif
	u_int8_t th_flags;
#define TH_FIN	0x01
#define TH_SYN	0x02
#define TH_RST	0x04
#define TH_PSH	0x08
#define TH_ACK	0x10
#define TH_URG	0x20
	u_int16_t th_win;	/* window */
	u_int16_t th_sum;	/* checksum */
	u_int16_t th_urp;	/* urgent pointer */
};
//icmp
struct icmp_header {
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int16_t icmp_chksum;
	u_int16_t icmp_id;
	u_int16_t icmp_seq;
};

#endif
