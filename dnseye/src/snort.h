#ifndef __SNORT_H__
#define __SNORT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*  I N C L U D E S  **********************************************************/
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>


/*  D E F I N E S  ************************************************************/

#ifdef SOLARIS
#define DEFAULT_INTF	"hme0"
#endif

#define DEFAULT_INTF	"eth0"


#ifdef FREEBSD
#define DEFAULT_INTF    "xl0"
#endif

#ifdef WORDS_BIGENDIAN
#define NETMASK 0xFFFFFF00
#else
#define NETMASK 0x00FFFFFF
#endif


#define ETHERNET_HEADER_LEN     14
#define ETHERNET_MTU            1500
#define ETHERNET_TYPE_IP        0x0800
#define ETHERNET_TYPE_ARP       0x0806
#define ETHERNET_TYPE_REVARP    0x8035
#define ETHERNET_TYPE_IPX       0x8137

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

#define TCPOPT_EOL      0
#define TCPOPT_NOP      1
#define TCPOPT_MAXSEG   2

#define L2TP_PORT 1701
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define SNAPLEN      1514
#define PROMISC      1
#define READ_TIMEOUT 500

#define ARPOP_REQUEST   1               /* ARP request                  */
#define ARPOP_REPLY     2               /* ARP reply                    */
#define ARPOP_RREQUEST  3               /* RARP request                 */
#define ARPOP_RREPLY    4               /* RARP reply                   */


#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
#define NR_ICMP_TYPES           18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH         15      /* instead of hardcoding immediate value */


#define STD_BUF  256

#define VERSION    "0.96"

#define RIGHT    1
#define LEFT     0

/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct progvars
{//程序变量
   int data_flag;
   int verbose_flag;
   int showarp_flag;
   int log_flag;
   int pkt_cnt; //数据包统计
   u_long homenet; //ip addr
   char config_file[STD_BUF];
   char log_dir[STD_BUF];
   char *interface;//网卡
   
   char *pcap_cmd;//bpf过滤规则
} PV;

typedef struct _EtherHdr
{
  unsigned char  ether_dst[6];
  unsigned char  ether_src[6];
  unsigned short ether_type;
} EtherHdr;



typedef struct _PrintIP
{
   u_char timestamp[64];
   u_char saddr[16];
   u_char daddr[16];
   u_short sport;
   u_short dport;
   u_long seq;
   u_long ack;
   u_char flags;
   char proto[5];
   u_long win;
   u_char ttl;
   u_short udp_len; 
   u_char icmp_str[64];
} PrintIP;



typedef struct _IPHdr
{
#if defined(WORDS_BIGENDIAN)
  u_char    ip_ver:4,\
              ip_hlen:4;
#else
  u_char    ip_hlen:4,\
              ip_ver:4;
#endif
  u_char   ip_tos;
  u_short   ip_len;
  u_short   ip_id;
  u_short   ip_off;
  u_char   ip_ttl;
  u_char   ip_proto;
  u_short   ip_csum;
  struct in_addr   ip_src;
  struct in_addr   ip_dst;
} IPHdr;


typedef struct _TCPHdr
{
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        u_long th_seq;                 /* sequence number */
        u_long th_ack;                 /* acknowledgement number */
#ifdef WORDS_BIGENDIAN
        u_char  th_off:4,               /* data offset */
                  th_x2:4;                /* (unused) */
#else
        u_char  th_x2:4,                /* (unused) */
                  th_off:4;               /* data offset */
#endif
        u_char  th_flags;
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
} TCPHdr;


typedef struct _UDPHdr
{
  u_short uh_sport;
  u_short uh_dport;
  u_short uh_len;
  u_short uh_chk;
} UDPHdr;   

typedef struct _ICMPhdr
{
  u_char type;
  u_char code;
  u_short csum;
} ICMPHdr;


typedef struct _echoext
{
  u_short id;
  u_short seqno;
} echoext;



typedef struct _ARPHdr
{
  unsigned short  ar_hrd;         /* format of hardware address   */
  unsigned short  ar_pro;         /* format of protocol address   */
  unsigned char   ar_hln;         /* length of hardware address   */
  unsigned char   ar_pln;         /* length of protocol address   */
  unsigned short  ar_op;          /* ARP opcode (command)         */
} ARPHdr;
  


typedef struct _EtherARP
{
  ARPHdr        ea_hdr;         /* fixed-size header */
  unsigned char arp_sha[6];     /* sender hardware address */
  unsigned char arp_spa[4];     /* sender protocol address */
  unsigned char arp_tha[6];     /* target hardware address */
  unsigned char arp_tpa[4];     /* target protocol address */
} EtherARP;


/*  G L O B A L S  ************************************************************/
PV pv;
int datalink;
char *progname;
char *pcap_cmd;
char *pktidx;
pcap_t *pd;
pcap_handler grinder;
PrintIP pip;
FILE *log_ptr;
int flow;

/*  P R O T O T Y P E S  ******************************************************/
int ParseCmdLine(int, char**);
int OpenPcap(char *);
int DisplayBanner();
int SetPktProcessor();
int DecodePkt();
void GetTime(char *);
void CleanExit();
void DecodeEthPkt(char *, struct pcap_pkthdr *, u_char *);
void DecodeSlipPkt(char *, struct pcap_pkthdr *, u_char *);
void DecodeRawPkt(char *, struct pcap_pkthdr *, u_char *);
void DecodeIP(u_char *, int);
void DecodeARP(u_char *, int, int);
void DecodeIPX(u_char *, int);
void DecodeTCP(u_char *, int);
void DecodeUDP(u_char *, int);
void DecodeICMP(u_char *, int);
void PrintIPPkt(FILE *, int);
void PrintNetData(FILE *, char *, int);
char *copy_argv(char **);
int OpenLogFile();
void SetFlow();

/*  D N S 2014.6 ******************************************************/

typedef struct _DNSHdr
{
	u_short id;
	u_short flags;
	u_short qdcount;
	u_short ancount;
	u_short nscount;
	u_short arcount;
}DNSHdr;
//son of second level ,namely, third level damin
struct SSLD{
	char name[64];
	u_long cnt;
	struct SSLD *next;
};
//second level domain, its length < 64
struct SLD{
	char name[64];
	u_long cnt;
	struct SSLD *ssld;
	struct SLD *next;
};
//top level domain
struct TLD{
	char name[5];
	u_long cnt;
	struct SLD *sld;
	struct TLD *next;
};
//requester, namely,src addr
struct DNSRequest{
	u_long saddr;
	u_long cnt;
	struct TLD *tld;
	struct DNSRequest *next;
};
//struct TLD *g_dnlist=NULL;
struct DNSRequest *g_dnslist=NULL;
static u_int pcnt;

void PrintDNlist(int level);
void ReleaseDNlist();
void RecordDomainName(u_long addr, char *dname);
void DecodeDNS(u_char *pkt, int len);
#endif  /* __SNORT_H__ */
