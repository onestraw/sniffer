/*********************************************************************
Program: catcher
Function: detect tcp/udp port scan
***********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <malloc.h>
#include <netinet/tcp.h>
#include <netinet/in_systm.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <syslog.h>
#include <linux/sockios.h>

#define LOG(info)	syslog(LOG_ALERT, "%s\n", info);fprintf(stdout,"%s\n",info)

#define PKTLEN 96    /* Should be enough for what we want */
#ifndef IP_MF
#define IP_MF    0x2000	/* Fragment bit*/
#endif

/***** WATCH LEVELS ******/

#define MYSELFONLY    1
#define MYSUBNET    2
#define HUMANITARIAN    3

/***** REPORT LEVELS *****/

#define REPORTALL    1
#define REPORTDOS    2
#define REPORTSCAN    3

/******STRUCT******/
//third level
struct dportNode{
    u_short dport;
	u_short sport;
	struct dportNode *next;
};
//second level
struct saddrNode {
    u_long saddr;
	u_long diff_dport_cnt;
	u_long high_freq_sport_cnt;//high frequency port, such as 80
	struct dportNode *dport;
    struct saddrNode *next;
};
//first level
struct daddrNode{
    u_long daddr;	//monitored ip addr
    struct saddrNode *tcp;	//for tcp scan
    struct saddrNode *udp;	//for udp scan
    struct daddrNode *next;
} ;
//main or monitored list
struct daddrNode *g_mlist = NULL;
struct daddrNode *g_pdaddr;


u_long g_my_addr;
time_t g_timer = 5, g_timein;

int g_portlimit = 7;
int g_hfreq_portlimit = 40;
//int Gsynflood = 8;
//int Gicmplimit = 5;
int Gwatchlevel = MYSELFONLY;
int Greportlevel = REPORTALL;
char *gProgramName;
char *gDev = "eth0";

/******** IP packet info, global ********/

u_long g_saddr, g_daddr;
u_int g_iplen, g_isfrag, g_id;

/****** Externals *************/

extern int errno;
extern int optind, opterr;
extern char *optarg;

void process_packet(), do_tcp(), do_udp(), do_icmp(), print_info();
void addtcp(), addudp(), clear_saddrNode(), buildnet();
void do_args(), usage(), addfloodinfo(), rmfloodinfo();
struct daddrNode *doicare(), *addtarget();
char *ip_itos();
u_char *readdevice();

/**** Program Entry ****/
int main(int argc, char *argv[])
{
    u_int pktlen = 0, i, netfd;
    u_char *pkt;
    char hostname[32];
    struct hostent *hp;
    time_t t;

    do_args(argc, argv);
    openlog("Fishnet", 0, LOG_DAEMON);

    if(gethostname(hostname, sizeof(hostname)) < 0)
    {
	    perror("gethostname()");
	    exit(-1);
    }
    if((hp = gethostbyname(hostname)) == NULL)
    {
	    fprintf(stderr, "Cannot find local address\n");
	    exit(-1);
    }
    memcpy((char *)&g_my_addr, hp->h_addr, hp->h_length);
    //g_my_addr = inet_addr("124.16.77.185");
	buildnet();
    if((netfd = initdevice(O_RDWR, 0)) < 0)
    	exit(-1);

    /* Now read packets forever and process them. */

    t = time((time_t *)0);
    while(pkt = readdevice(netfd, &pktlen))
    {
	    process_packet(pkt, pktlen);
	    if(time((time_t *)0) - t > g_timer)
	    {
			/* Times up.  Print what we found and clean out old stuff. */
			for(g_pdaddr = g_mlist; g_pdaddr; g_pdaddr = g_pdaddr->next)
			{
				print_info();
				clear_saddrNode(g_pdaddr);			
			}
			t = time((time_t *)0);
	    }
    }
	return 0;
}

/**********************************************************************
Function: do_args

Purpose:  sets values from environment or command line arguments.
**********************************************************************/
void do_args(int argc, char *argv[])
{
    char c;

    gProgramName = argv[0];
    while((c = getopt(argc,argv,"d:h:m:p:r:t:w:")) != EOF)
    {
        switch(c)
        {
        case 'd':
        	gDev = optarg;
        	break;
        case 'h':
		    usage();
		    exit(0);
        case 'm':
		    if(strcmp(optarg, "all") == 0)
		        Gwatchlevel = HUMANITARIAN;
		    else if(strcmp(optarg, "subnet") == 0)
		        Gwatchlevel = MYSUBNET;
		    else
		    {
		        usage();
		        exit(-1);
		    }
		    break;
        case 'p':
		    g_portlimit = atoi(optarg);
		    break;
        case 'r':
		    if(strcmp(optarg, "dos") == 0)
		        Greportlevel = REPORTDOS;
		    else if(strcmp(optarg, "scan") == 0)
		        Greportlevel = REPORTSCAN;
		    else
		    {
				usage();
		        exit(-1);
		    }
		    break;
        case 't':
        	g_timer = atoi(optarg);
        	break;
        case 'w':
		    g_hfreq_portlimit = atoi(optarg);
		    break;
        default:
        	usage();
        	exit(-1);
        }
    }
}

/**********************************************************************
Function: usage

Purpose:  Display the usage of the program
**********************************************************************/
void usage()
{
	printf("Usage: %s [options]\n", gProgramName);
	printf("  -d device       Use 'device' as the network interface device\n");
	printf("                  The first non-loopback interface is the default\n");
	printf("  -f flood        Assume a synflood attack occurred if more than\n");
	printf("                  'flood' uncompleted connections are received\n");
	printf("  -h              A little help here\n");
	printf("  -i icmplimit    Assume we may be part of a smurf attack if more\n");
	printf("                  than icmplimit ICMP ECHO REPLIES are seen\n");
	printf("  -m level        Monitor more than just our own host.\n");
	printf("                  A level of 'subnet' watches all addresses in our\n");
	printf("                  subnet and 'all' watches all addresses\n");
	printf("  -p portlimit    Logs a portscan alert if packets are received for\n");
	printf("                  more than portlimit ports in the timeout period.\n");
	printf("  -r reporttype   If reporttype is dos, only Denial Of Service\n");
	printf("                  attacks are reported.  If reporttype is scan\n");
	printf("                  then only scanners are reported.  Everything is\n");
	printf("                  reported by default.\n");
	printf("  -t timeout      Count packets and print potential attacks every\n");
	printf("                  timeout seconds\n");
	printf("  -w webcount     Assume we are being portscanned if more than\n");
	printf("                  webcount packets are received from port 80\n");
}

/**********************************************************************
Function: buildnet

Purpose:  Setup for monitoring of our host or entire subnet.
**********************************************************************/
void buildnet()
{
    u_long addr;
    u_char *p;
    int i;

    if(Gwatchlevel == MYSELFONLY)        /* Just care about me */
    {
    	(void) addtarget(g_my_addr);
    }
    else if(Gwatchlevel == MYSUBNET)        /* Friends and neighbors */
    {
	    addr = htonl(g_my_addr);
	    addr = addr & 0xffffff00;
	    for(i = 0; i < 256; i++)
			(void) addtarget(ntohl(addr + i));
    }
    
    struct daddrNode *di;
    for(di = g_mlist; di; di=di->next)
    	printf("%s\n",ip_itos(di->daddr));
    
}
/**********************************************************************
Function: doicare
do I care ?
Purpose:  See if we monitor this address
**********************************************************************/
struct daddrNode *doicare(u_long addr)
{
    struct daddrNode *pdip;
    int i;

    for(pdip = g_mlist; pdip; pdip = pdip->next)
    {
	    if(pdip->daddr == addr)
			return(pdip);
    }
    if(Gwatchlevel == HUMANITARIAN)    /* Add a new address, we always care */
    {
	    pdip = addtarget(addr);
	    return(pdip);
    }
    return(NULL);
}

/**********************************************************************
Function: addtarget

Purpose:  Adds a new IP address to the list of hosts to watch.
**********************************************************************/
struct daddrNode *addtarget(u_long addr)
{
    struct daddrNode *pdip;

    if((pdip = (struct daddrNode *)malloc(sizeof(struct daddrNode))) == NULL)
    {
	    perror("malloc daddrNode");
	    exit(-1);
    }
    memset(pdip, 0, sizeof(struct daddrNode));
	pdip->daddr = addr;
    pdip->next = g_mlist;
    g_mlist = pdip;
    return(pdip);
}

/**********************************************************************
Function: process_packet

Purpose:  Process raw packet and figure out what we need to to with it.

Pulls the packet apart and stores key data in global areas for reference
by other functions.
**********************************************************************/
void process_packet(pkt, pktlen)
u_char *pkt;
u_int pktlen;
{
    struct ethhdr *ep;
    struct iphdr *ip;
    static struct align { struct iphdr ip; char buf[PKTLEN]; } a1;
    u_short off;

    g_timein = time((time_t *)0);
    ep = (struct ethhdr *)pkt;
    if(ntohs(ep->h_proto) != ETH_P_IP)
	    return;

    pkt += sizeof(struct ethhdr);
    pktlen -= sizeof(struct ethhdr);
    memcpy(&a1, pkt, pktlen);
    ip = &a1.ip;
    g_saddr = ip->saddr;
    g_daddr = ip->daddr;

    if((g_pdaddr = doicare(g_daddr)) == NULL)/* 遍历g_mlist */
	    return;

    off = ntohs(ip->frag_off);
    g_isfrag = (off & IP_MF);    /* Set if packet is fragmented */
    g_iplen = ntohs(ip->tot_len);
    g_id = ntohs(ip->id);
    pkt = (u_char *)ip + (ip->ihl << 2);
    g_iplen -= (ip->ihl << 2);
    switch(ip->protocol)
    {
	    case IPPROTO_TCP:
			do_tcp(ep, pkt);
			break;
	    case IPPROTO_UDP:
			do_udp(ep, pkt);
			break;
	    default:
			break;
    }
}

/**********************************************************************
Function: do_tcp

Purpose:  Process this TCP packet if it is important.
**********************************************************************/
void do_tcp(ep, pkt)
struct ethhdr *ep;
u_char* pkt;
{
    struct tcphdr *thdr;
    u_short sport, dport;

    thdr = (struct tcphdr *) pkt;
	/*如果响应是RST包，可能说明被扫描的端口是关闭的*/
    if(thdr->rst) /* RST generates no response */
    	return;            /* Therefore can't be used to scan. */
    sport = ntohs(thdr->source);
    dport = ntohs(thdr->dest);

	u_short flags=0;
	flags = thdr->syn<<2 + thdr->fin<<1 + thdr->ack;
    addtcp(sport, dport, flags, ep->h_source);
}
/**********************************************************************
Function: createPortNode

Purpose:  create a new dportNode and add it to saddrNode.
**********************************************************************/
void createPortNode(struct saddrNode *psa, u_short sport, u_short dport)
{
	struct dportNode *pdp;
	if((pdp = (struct dportNode *)malloc(sizeof(struct dportNode))) == NULL)
	{
		perror("Malloc dportNode");
		exit(-1);
	}
	pdp->sport = sport;
	pdp->dport = dport;
	pdp->next=psa->dport;
	psa->dport = pdp;
}

/**********************************************************************
Function: addtcp

Purpose:  Add this TCP packet to our list.
**********************************************************************/
void addtcp(sport,dport,flags,eaddr)
u_short sport;
u_short dport;
u_char flags;
u_char *eaddr;
{
    struct saddrNode *pi;
	struct dportNode *pdp;
    /* See if this packet relates to other packets already received. */

    for(pi = g_pdaddr->tcp; pi; pi = pi->next)
    {
		if(pi->saddr == g_saddr)
		{
			if(sport==80)
				pi->high_freq_sport_cnt ++;
			for(pdp = pi->dport;pdp; pdp = pdp->next)
				if(pdp->dport==dport)
					return;
			/* Must be new dport */
			createPortNode(pi, sport, dport);
			pi->diff_dport_cnt ++;
			return;	
		}
    }
    /* Must be new saddr */

    if((pi = (struct saddrNode *)malloc(sizeof(struct saddrNode))) == NULL)
    {
		perror("Malloc saddrNode");
		exit(-1);
    }
    memset(pi, 0, sizeof(struct saddrNode));

    pi->saddr = g_saddr;
	pi->diff_dport_cnt = 1;
	pi->high_freq_sport_cnt = 1;
	pi->next = g_pdaddr->tcp;
	g_pdaddr->tcp = pi;
	
	/* Add a new dport */
	createPortNode(g_pdaddr->tcp, sport, dport);
}

/**********************************************************************
Function: do_udp

Purpose:  Process this udp packet.

Currently teardrop and all its derivitives put 242 in the IP id field.
This could obviously be changed.  The truly paranoid might want to flag all
fragmented UDP packets.  The truly adventurous might enhance the code to
track fragments and check them for overlaping boundaries.
**********************************************************************/
void do_udp(ep, pkt)
struct ethhdr *ep;
u_char *pkt;
{
    struct udphdr *uhdr;
    u_short sport, dport;

    uhdr = (struct udphdr *) pkt;

    sport = ntohs(uhdr->source);
    dport = ntohs(uhdr->dest);
    addudp(sport, dport, ep->h_source);
}

/**********************************************************************
Function: addudp

Purpose:  Add this udp packet to our list.
**********************************************************************/
void addudp(sport, dport, eaddr)
u_short sport;
u_short dport;
u_char *eaddr;
{
    struct saddrNode *pi;
	struct dportNode *pdp;
    for(pi = g_pdaddr->udp; pi; pi = pi->next)
    {
		if(pi->saddr == g_saddr)
		{
			if(sport==80)
				pi->high_freq_sport_cnt ++;
			for(pdp = pi->dport;pdp; pdp = pdp->next)
				if(pdp->dport==dport)
					return;

			/* Must be new dport */
			createPortNode(pi, sport, dport);
			pi->diff_dport_cnt ++;
			return;
		}
    }
    /* Must be new entry */

    if((pi = (struct saddrNode *)malloc(sizeof(struct saddrNode))) == NULL)
    {
		perror("Malloc saddrNode");
		exit(-1);
    }
    memset(pi, 0, sizeof(struct saddrNode));

    pi->saddr = g_saddr;
	pi->diff_dport_cnt = 1;
	pi->high_freq_sport_cnt = 1;
	pi->next = g_pdaddr->udp;
	g_pdaddr->udp = pi;
	
	/* Add a new dport */
	createPortNode(g_pdaddr->udp, sport, dport);
}


/**********************************************************************
Function: clear_saddrNode

Purpose:  Delete and free space for all packets.释放第二层和第三层
**********************************************************************/
void clear_saddrNode(di)
struct daddrNode *di;
{
    struct saddrNode *si;
	struct dportNode *pi,*tpi;

    while(di->tcp)
    {
		si = di->tcp;
		pi = si->dport;
		while(pi)
		{
			tpi = pi;
			pi = pi->next;
			free(tpi);
		}
		di->tcp = si->next;
		free(si);
    }
    while(di->udp)
    {
		si = di->udp;
		pi = si->dport;
		while(pi)
		{
			tpi = pi;
			pi = pi->next;
			free(tpi);
		}
		di->udp = si->next;
		free(si);
    }
}

/**********************************************************************
Function: print_info

Purpose:  Print out any alerts.
**********************************************************************/
void print_info()
{
    struct saddrNode *si;

    char buf[1024], abuf[16];

    strcpy(abuf, ip_itos(g_pdaddr->daddr));

    if(Greportlevel == REPORTALL || Greportlevel == REPORTSCAN)
    {
        
        for(si = g_pdaddr->tcp; si; si = si->next)
		{
			if((si->diff_dport_cnt - si->high_freq_sport_cnt > g_portlimit)||
						si->high_freq_sport_cnt>g_hfreq_portlimit)
			{
				sprintf(buf, "Possible TCP port scan from %s (%lu ports) against %s\n",ip_itos(si->saddr), si->diff_dport_cnt, abuf);
					LOG(buf);
			}
		}
		for(si = g_pdaddr->udp; si; si = si->next)
		{
			if((si->diff_dport_cnt - si->high_freq_sport_cnt > g_portlimit)||
						si->high_freq_sport_cnt>g_hfreq_portlimit)
			{
				sprintf(buf, "Possible UDP port scan from %s (%lu ports) against %s\n",ip_itos(si->saddr), si->diff_dport_cnt , abuf);
					LOG(buf);
			}
		}
    }

}

/************************************************************************
Function:  ip_itos

Description: convert ip address from u_long to char*.

**************************************************************************/
char *ip_itos(addr)
u_long addr;
{
	static char buf[16];
	inet_ntop(AF_INET,(void*)&addr, buf,16);
	return (buf);
}

/************************************************************************
Function:  initdevice

Description: Set up the network device so we can read it.

**************************************************************************/
initdevice(fd_flags, dflags)
int fd_flags;
u_long dflags;
{
    struct ifreq ifr;
    int fd, flags = 0;

    if((fd = socket(PF_INET, SOCK_PACKET, htons(0x0003))) < 0)
    {
		perror("Cannot open device socket");
		exit(-1);
    }

    /* Get the existing interface flags */
    strcpy(ifr.ifr_name, gDev);
    if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
    {
		perror("Cannot get interface flags");
		exit(-1);
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if(ioctl(fd, SIOCSIFFLAGS,  &ifr) < 0)
    {
		perror("Cannot set interface flags");
		exit(-1);
    }
    
    return(fd);
}

/************************************************************************
Function:  readdevice

Description: Read a packet from the device.

**************************************************************************/
u_char *readdevice(fd, pktlen)
int fd;
int *pktlen;
{
    int cc = 0, from_len, readmore = 1;
    struct sockaddr from;
    static u_char pktbuffer[PKTLEN];
    u_char *cp;

    while(readmore)
    {
		from_len = sizeof(from);
		if((cc = recvfrom(fd, pktbuffer, PKTLEN, 0, &from, &from_len)) < 0)
		{
			if(errno != EWOULDBLOCK)
			return(NULL);
		}
		if(strcmp(gDev, from.sa_data) == 0)
			readmore = 0;
    }
    *pktlen = cc;
    return(pktbuffer);
}
