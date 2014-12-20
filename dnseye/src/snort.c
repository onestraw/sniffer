/*
** Copyright (C) 1998 Martin Roesch <roesch@clark.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/******************************************************************************
 *
 * Program: Snort
 *
 * Purpose: This is a fairly generic sniffing program which does some nice
 *          logging.  You can tell it what the "home" network is and it will
 *          log all traffic in terms of the remote side of the connection.
 *          The program can take BPF-style filtering commands at the command
 *          line and filter out the packets it receives to just the network
 *          of interest.
 *
 * Author: Martin Roesch (mroesch@bbn.com) (roesch@clark.net)
 *
 * Last Modified: 12/21/98
 *
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab program.
 *           Check out his stuff at http://www.xnet.com/~cathmike/MSB/
 *
 ******************************************************************************/

/*  I N C L U D E S  **********************************************************/
#include "snort.h"

/****************************************************************************
 *
 * Function: main(int, char *)
 *
 * Purpose:  Handle program entry and exit, call main prog sections
 *
 * Arguments: -d => dump the application layer data
 *            -a => display ARP packets
 *            -n => exit after receiving x packets
 *            -i => listen on interface x
 *            -l => log to directory x
 *            -h => set "home" network to x
 *            -v => be verbose
 *            -V => show the version number and exit
 *            -? => show the program help data and exit
 *            list => a list of BPF commands can also be sent to the program
 *                    to control what data gets captured
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 ****************************************************************************/
int main(int argc, char *argv[])
{
   /* grab a few signals to make sure we a good about cleaning up */
   signal(SIGKILL, CleanExit);
   signal(SIGTERM, CleanExit);
   signal(SIGINT, CleanExit);
   signal(SIGQUIT, CleanExit);
   signal(SIGHUP, CleanExit);

   /* set a global ptr to the program name so other functions can tell
      what the program name is */
   progname = argv[0];

   if(getuid())
   {
      fprintf(stderr, "Sorry Pard'ner, you gotta be at least this tall to ride this pony.\n");
      fprintf(stderr, "--->root\n");
      fprintf(stderr, "|\n");
      fprintf(stderr, "|\n");
      fprintf(stderr, "|\n");
      fprintf(stderr, "|\n");
      fprintf(stderr, "|\n");
      CleanExit();
   } 
   /* Tell 'em who wrote it, and what "it" is */
   DisplayBanner();

   /* initialize the packet counter to loop forever */
   pv.pkt_cnt = -1;

   /* chew up the command line */
   ParseCmdLine(argc, argv);

   /* if no interface has been indicated, set the default to eth0 (my Linux
      bias is showing thru */
   if(pv.interface == NULL)
   {
      pv.interface = (u_char *) malloc((sizeof(char) * strlen(DEFAULT_INTF)));
      bzero(pv.interface, strlen(DEFAULT_INTF));
      strncpy(pv.interface, DEFAULT_INTF, strlen(DEFAULT_INTF));
   }

   /* open up our libpcap packet capture interface */
   OpenPcap(pv.interface);

   /* set the packet processor (ethernet, slip or raw)*/
   SetPktProcessor();

  /* Read all packets on the device.  Continue until cnt packets read */
  if(pcap_loop(pd, pv.pkt_cnt, grinder, NULL) < 0)
  {
     fprintf(stderr, "pcap_loop: %s", pcap_geterr(pd));
     CleanExit();
  }

  /* close the capture interface */
  pcap_close(pd);

  return 0;
}



/****************************************************************************
 *
 * Function: ShowUsage(char *)
 *
 * Purpose:  Display the program options and exit
 *
 * Arguments: progname => name of the program (argv[0])
 *
 * Returns: 0 => success
 *
 ****************************************************************************/
int ShowUsage(char *progname)
{
   printf("\nUSAGE: %s [-options] <filter options>\n", progname);
   printf("Options:\n");
   printf("         -a         Display ARP packets\n");
   printf("         -d         Dump the Application Layer\n");
   printf("         -h <hn>    Home network = <hn>\n");
   printf("         -i <if>    Listen on interface <if>\n");
   printf("         -l <ld>    Log to directory <ld>\n");
   printf("         -n <i>     Exit after receiving <cnt> packets\n");
   printf("         -v         Be verbose\n");
   printf("         -V         Show version number\n");
   printf("         -?         Show this information\n");
   printf("<Filter Options> are standard BPF options, as seen in TCPDump\n");
   printf("\n");

   fflush(stdout);

   return 0;
}




/****************************************************************************
 *
 * Function: ParseCmdLine(int, char *)
 *
 * Purpose:  Parse command line args
 *
 * Arguments: argc => count of arguments passed to the routine
 *            argv => 2-D character array, contains list of command line args
 *
 * Returns: 0 => success, 1 => exit on error
 *
 ****************************************************************************/
int ParseCmdLine(int argc, char *argv[])
{
   char ch;                      /* storage var for getopt info */
   extern char *optarg;          /* for getopt */
   extern int optind;            /* for getopt */
   struct in_addr net;           /* place to stick the local network data */

#ifdef DEBUG
   printf("Parsing command line...\n");
#endif

   /* loop through each command line var and process it */
   while((ch = getopt(argc, argv, "h:l:dn:i:vV?a")) != EOF)
   {
#ifdef DEBUG
      printf("Processing cmd line switch: %c\n", ch);
#endif
      switch(ch)
      {
         case 'l': /* use log dir <X> */
                 strncpy(pv.log_dir, optarg, STD_BUF-1);
#ifdef DEBUG
                 printf("Log directory = %s\n", pv.log_dir);
#endif
                 pv.log_flag = 1;
                 break;

         case 'a': /* show ARP packets */
#ifdef DEBUG
                 printf("Show ARP active\n");
#endif
                 pv.showarp_flag = 1;
                 
                 break;

         case 'd': /* dump the application layer data */
                 pv.data_flag = 1;
#ifdef DEBUG
                 printf("Data Flag active\n");
#endif
                 break;

         case 'v': /* be verbose */
                 pv.verbose_flag = 1;
#ifdef DEBUG
                 printf("Verbose Flag active\n");
#endif
                 break;

         case 'n': /* grab x packets and exit */
                 pv.pkt_cnt = atoi(optarg);
#ifdef DEBUG
                 printf("Exiting after %d packets\n", pv.pkt_cnt);
#endif
                 break;


         case 'i': /* listen on interface x */
                 pv.interface = (u_char *) malloc(strlen(optarg));
                 bzero(pv.interface, strlen(optarg));
                 strncpy(pv.interface, optarg, strlen(optarg));
#ifdef DEBUG
                 printf("Interface = %s\n", pv.interface);
#endif
                 break;

         case '?': /* show help and exit */
                 ShowUsage(progname);
                 exit(0);

         case 'V': /* prog ver already gets printed out, so we just exit */
                 exit(0);

         case 'h': /* set home network to x, this will help determine what to
                      set logging diectories to */
                 if((net.s_addr = inet_addr(optarg)) ==-1)
                 {
                    fprintf(stderr, "ERROR: Homenet (%s) didn't x-late, WTF?\n",
                            optarg);
                    exit(0);
                 }
                 else
                 {
#ifdef DEBUG
                    struct in_addr sin;
                    printf("Net = %s (%lX)\n", inet_ntoa(net), net.s_addr);
#endif
                    /* we assume a class C network for the time being */
                    pv.homenet = ((u_long)net.s_addr & NETMASK); 
#ifdef DEBUG
                    sin.s_addr = pv.homenet;
                    printf("Homenet = %s (%lX)\n", inet_ntoa(sin), sin.s_addr);
#endif
                 }

                 break;
      }
   }

   /* set the BPF rules string (thanks Mike!) */
   pv.pcap_cmd = copy_argv(&argv[optind]);

#ifdef DEBUG
   if(pv.pcap_cmd != NULL)
   {
      printf("pcap_cmd = %s\n", pv.pcap_cmd);
   }
   else
   {
      printf("pcap_cmd is NULL!\n");
   }
#endif

   return 0;
}


/****************************************************************************
 *
 * Function: SetPktProcessor()
 *
 * Purpose:  Set which packet processing function we're going to use based on 
 *           what type of datalink layer we're using
 *
 * Arguments: None.
 *
 * Returns: 0 => success
 *
 ****************************************************************************/
int SetPktProcessor()
{
   switch(datalink)
   {
      case DLT_EN10MB:
                printf("Decoding Ethernet on interface %s\n", pv.interface);
                grinder = (pcap_handler) DecodeEthPkt;
                break;

      case DLT_SLIP:
                printf("Decoding Slip on interface %s\n", pv.interface);
                grinder = (pcap_handler) DecodeSlipPkt;
                break;

#ifdef DLT_RAW /* Not supported in some arch or older pcap versions */
      case DLT_RAW:
                printf("Decoding raw data on interface %s\n", pv.interface);
                grinder = (pcap_handler) DecodeRawPkt;
                break;
#endif

       default:
                fprintf(stderr, "\n%s cannot handle data link type %d", 
                        progname, datalink);
                CleanExit();
    }
 
   return 0;
}
   

/****************************************************************************
 *
 * Function: OpenPcap(char *)
 *
 * Purpose:  Open the libpcap interface
 *
 * Arguments: intf => name of the interface to open 
 *
 * Returns: 0 => success, exits on problems
 *
 ****************************************************************************/
int OpenPcap(char *intf)
{
   bpf_u_int32 localnet, netmask;    /* net addr holders */
   struct bpf_program fcode;         /* Finite state machine holder */
   char errorbuf[PCAP_ERRBUF_SIZE];  /* buffer to put error strings in */
 
   /* look up the device and get the handle */
   if(pv.interface == NULL)
   {
      pv.interface = pcap_lookupdev(errorbuf);

      if(pv.interface == NULL)
      {
         fprintf(stderr, "ERROR: OpenPcap() device %s lookup: %s\n", 
                 pv.interface, errorbuf);
         CleanExit();
      }
   }
 
   /* get the device file descriptor */
   pd = pcap_open_live(pv.interface, SNAPLEN, PROMISC, READ_TIMEOUT, errorbuf);

   if (pd == NULL) 
   {
      fprintf(stderr, "ERROR: OpenPcap() device %s open: %s\n", 
              pv.interface, errorbuf);
      CleanExit();
   }
 
   /* get local net and netmask */
   if(pcap_lookupnet(pv.interface, &localnet, &netmask, errorbuf) < 0)
   {
      fprintf(stderr, "ERROR: OpenPcap() device %s network lookup: %s\n", 
              pv.interface, errorbuf);
      CleanExit();
   }
  
   /* compile command line filter spec info fcode FSM */
   if(pcap_compile(pd, &fcode, pv.pcap_cmd, 0, netmask) < 0)
   {
      fprintf(stderr, "ERROR: OpenPcap() FSM compilation failed: %s\n", 
              pcap_geterr(pd));
      CleanExit();
   } 
  
   /* set the pcap filter */
   if(pcap_setfilter(pd, &fcode) < 0)
   {
      fprintf(stderr, "ERROR: OpenPcap() setfilter: %s\n", pcap_geterr(pd));
      CleanExit();
   }
 
   /* get data link type */
   datalink = pcap_datalink(pd);

   if (datalink < 0) 
   {
      fprintf(stderr, "ERROR: OpenPcap() datalink grab: %s\n", pcap_geterr(pd));
      CleanExit();
   }

   return 0;
}
 
/****************************************************************************
 *
 * Function: CleanExit()
 *
 * Purpose:  Clean up misc file handles and such and exit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void CleanExit()
{
   printf("Exiting...\n");

   pcap_close(pd);

   if(pv.log_flag)
      fclose(log_ptr);
   if(g_dnslist)
   {
      PrintDNlist(3);
      ReleaseDNlist();
   }
   exit(0);
}


/****************************************************************************
 *
 * Function: DisplayBanner()
 *
 * Purpose:  Show valuable proggie info
 *
 * Arguments: None.
 *
 * Returns: 0 all the time
 *
 ****************************************************************************/
int DisplayBanner()
{
   printf("\n-*> Snort! <*-\nVersion %s, By Martin Roesch (roesch@clark.net)\n", VERSION);
   return 0;
}



/****************************************************************************
 *
 * Function: DecodeEthPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has 
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeEthPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   int pkt_len;  /* suprisingly, the length of the packet */
   int cap_len;  /* caplen value */
   int pkt_type; /* type of pkt (ARP, IP, etc) */
   EtherHdr *eh; /* ethernet header pointer (thanks Mike!) */

   /* set the lengths we need */
   pkt_len = pkthdr->len;
   cap_len = pkthdr->caplen;

#ifdef DEBUG
   printf("Packet!\n");
#endif

   /* do a little validation */
   if(cap_len < ETHERNET_HEADER_LEN)
   {
      fprintf(stderr, "Ethernet header length < cap len! (%d bytes)\n", 
              cap_len);
      return;
   }   

   /* lay the ethernet structure over the packet data */
   eh = (EtherHdr *) pkt;

   /* grab out the network type */
   pkt_type = ntohs(eh->ether_type);

   /* set the packet index pointer */
   pktidx = pkt;

   /* increment the index pointer to the start of the network layer */
   pktidx += ETHERNET_HEADER_LEN;

   switch(pkt_type)
   {
      case ETHERNET_TYPE_IP:
#ifdef DEBUG
                      printf("IP Packet\n");
#endif
                      DecodeIP(pktidx, pkt_len-ETHERNET_HEADER_LEN);
                      return;

      case ETHERNET_TYPE_ARP:
      case ETHERNET_TYPE_REVARP:
                      if(pv.showarp_flag)
                         DecodeARP(pktidx, pkt_len-ETHERNET_HEADER_LEN, cap_len);
                      return;

      case ETHERNET_TYPE_IPX:
                      DecodeIPX(pktidx, (pkt_len-ETHERNET_HEADER_LEN));
                      return;
      default:
             return;
   }

   return;
}



/****************************************************************************
 *
 * Function: DecodeSlipPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: For future expansion
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeSlipPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
}



/****************************************************************************
 *
 * Function: DecodeRawPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: For future expansion
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeRawPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
}



/****************************************************************************
 *
 * Function: DecodeIP(u_char *, int)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIP(u_char *pkt, int len)
{
   IPHdr *iph;   /* ip header ptr */
   u_int ip_len; /* length from the start of the ip hdr to the pkt end */
   u_int hlen;   /* ip header length */
   u_int off;    /* data offset */


   bzero((void *) &pip, sizeof(PrintIP));

   /* lay the IP struct over the raw data */
   iph = (IPHdr *) pkt;

#ifdef DEBUG
   printf("ip header starts at: %p\n", iph);
#endif

   /* do a little validation */
   if(len < sizeof(IPHdr))
   {
      fprintf(stderr, "Truncated header! (%d bytes)\n", len);
      return;
   }
  
   ip_len = ntohs(iph->ip_len);

   if(len < ip_len)
   {
      fprintf(stderr, 
              "Truncated packet!  Header says %d bytes, actually %d bytes\n", 
              ip_len, len);
      return;
   }

   /* set the IP header length */
   hlen = iph->ip_hlen * 4;      

   /* generate a timestamp */
   GetTime(pip.timestamp);

   /* start filling in the printout data structures */
   strncpy(pip.saddr, inet_ntoa(iph->ip_src), 15);
   strncpy(pip.daddr, inet_ntoa(iph->ip_dst), 15);

#ifdef DEBUG
   printf("Src addr = %s\n", pip.saddr);
   printf("Dst addr = %s\n", pip.daddr);
#endif
   
   pip.ttl = iph->ip_ttl;

   /* check for fragmented packets */
   ip_len -= hlen;
   off = ntohs(iph->ip_off);

#ifdef DEBUG
   printf("off = %X:%X\n", off, (off & 0x1FFF));
#endif

   if((off & 0x1FFF) == 0)
   { 
#ifdef DEBUG
      printf("IP header length: %d\n", hlen);
#endif

      /* move the packet index to point to the transport layer */
      pktidx = pktidx + hlen;

      switch(iph->ip_proto)
      {
         case IPPROTO_TCP:
                      strncpy(pip.proto, "TCP", 3);
                      DecodeTCP(pktidx, len-hlen);
                      return;

         case IPPROTO_UDP:
                      strncpy(pip.proto, "UDP", 3);
                      DecodeUDP(pktidx, len-hlen);
                      return;

         case IPPROTO_ICMP:
                      strncpy(pip.proto, "ICMP", 4);
                      DecodeICMP(pktidx, len-hlen);
                      return;

         default: 
                return;

      }
   }
}



/****************************************************************************
 *
 * Function: DecodeTCP(u_char *, int)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeTCP(u_char *pkt, int len)
{
   TCPHdr *tcph;  /* TCP packet header ptr */
   int hlen;      /* TCP header length */

   /* lay TCP on top of the data */
   tcph = (TCPHdr *) pkt;

#ifdef DEBUG
   printf("tcp header starts at: %p\n", tcph);
#endif

   /* stuff more data into the printout data struct */
   pip.sport = ntohs(tcph->th_sport);
   pip.dport = ntohs(tcph->th_dport);
#ifdef DEBUG
   printf("s-port = %d:%d   d-port = %d:%d\n", pip.sport, tcph->th_sport, pip.dport, tcph->th_dport);
#endif

   pip.seq = ntohl(tcph->th_seq);
   pip.ack = ntohl(tcph->th_ack);

   pip.win = ntohs(tcph->th_win);
   pip.flags = tcph->th_flags;
   hlen = tcph->th_off * 4;

   SetFlow();

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_TCP);
  
      if(pv.data_flag)
         PrintNetData(stdout, (char *) (pkt + hlen), len-hlen);
   }

   if(pv.log_flag)
   {
      OpenLogFile();

      PrintIPPkt(log_ptr, IPPROTO_TCP);
  
      if(pv.data_flag)
         PrintNetData(log_ptr, (char *) (pkt + hlen), len-hlen);

      fclose(log_ptr);
   }
}

void PrintDNlist(int level)
{
	struct DNSRequest *dnsr;
	struct TLD *tld;
	struct SLD *sld;
	struct SSLD *ssld;
	struct in_addr saddr;
	for(dnsr=g_dnslist; dnsr; dnsr=dnsr->next)
	{
		saddr.s_addr = dnsr->saddr;
		fprintf(stdout,"From: %s\tCount: %lu\n",inet_ntoa(saddr),dnsr->cnt);
		for(tld = dnsr->tld; tld; tld=tld->next)
		{
			fprintf(stdout,"+%s\tCount:%lu\n",tld->name,tld->cnt);
			for(sld = tld->sld; sld; sld=sld->next)
			{
				fprintf(stdout,"-+%s.%s\tCount:%lu\n",sld->name,tld->name,sld->cnt);
				for(ssld = sld->ssld; ssld && level>2; ssld=ssld->next)
					fprintf(stdout,"---%s.%s.%s\n",ssld->name,sld->name,tld->name);	
			}
				
		}
	}
}
void ReleaseDNlist()
{
	struct DNSRequest *dnsr;
	struct TLD *tld;
	struct SLD *sld;
	struct SSLD *ssld;
	while(dnsr = g_dnslist)
	{
		while(tld = dnsr->tld)
		{
			while(sld = tld->sld)
			{
				while(ssld = sld->ssld)
				{
					sld->ssld = ssld->next;
					free(ssld);
				}
				tld->sld = sld->next;
				free(sld);
			}
			dnsr->tld = tld->next;
			free(tld);
		}
		g_dnslist = dnsr->next;
		free(dnsr);
	}
}

void RecordDomainName(u_long saddr, char *dname)
{
	char name1[5],name2[64],name3[64];
	int i,j,k,len, idx[3];
	len= strlen(dname);
	
	for(i=0,j=0; i<len && j<3; i++)
		if(dname[i]=='.')
			idx[j++]=i;
	if(j<1)
		return;
	else if(j==3)
	{
		for(i=len-1,j=2; i>-1 &&j>-1; i--)
			if(dname[i]=='.')
				idx[j--]=i;
		j=3;
	}
	memset(name1,0,5);
	memset(name2,0,64);
	memset(name3,0,64);
	i=idx[--j]+1;
	k=0; 
	while(i<len)
		name1[k++] = dname[i++];
	if(j<1)
	{
		i=0;
		j=-1;
	}
	else
	{
		i=idx[--j]+1;
	}
	k=0;
	while(i<idx[j+1])
		name2[k++] = dname[i++];
		
	if(j<0)
		name3[0]='\0';
	else
		for(i=0,k=0; i<idx[j]; i++)
			name3[k++] = dname[i];
	printf("%s\t%s\t%s\n",name1,name2,name3);
	/* insert the domain name into g_dnlist */
	//first level
	struct DNSRequest *dnsr;
	for(dnsr=g_dnslist; dnsr; dnsr=dnsr->next)
		if(saddr = dnsr->saddr)
			break;
	if(!dnsr)
	{
		if((dnsr = (struct DNSRequest*)malloc(sizeof(struct DNSRequest)))==NULL)
		{
			fprintf(stderr,"malloc DNSRequest error\n");
			exit(-1);
		}
		memset(dnsr,0,sizeof(struct DNSRequest));
		dnsr->saddr = saddr;
		dnsr->next = g_dnslist;
		g_dnslist = dnsr;
	}
	dnsr->cnt++;
	//second level
	struct TLD *tld;
	for(tld=dnsr->tld; tld; tld=tld->next)
		if(strcmp(tld->name, name1)==0)
			break;
	if(!tld)//create a new TLD node
	{
		if((tld = (struct TLD*)malloc(sizeof(struct TLD)))==NULL)
		{
			fprintf(stderr,"malloc TLD error\n");
			exit(-1);
		}
		memset(tld,0,sizeof(struct TLD));
		strcpy(tld->name, name1);
		tld->next = dnsr->tld;
		dnsr->tld = tld;
	}
	tld->cnt ++;
	//third level
	struct SLD *sld;
	for(sld = tld->sld; sld; sld=sld->next)
		if(strcmp(sld->name, name2)==0)
			break;
	if(!sld)
	{
		if((sld = (struct SLD*)malloc(sizeof(struct SLD)))==NULL)
		{
			fprintf(stderr,"malloc SLD error\n");
			exit(-1);
		}
		memset(sld,0,sizeof(struct SLD));
		strcpy(sld->name, name2);
		sld->next = tld->sld;
		tld->sld = sld;
	}
	sld->cnt++;
	if(name3[0]=='\0')
		return;
	//fourth level
	struct SSLD *ssld;
	for(ssld=sld->ssld; ssld; ssld=ssld->next)
		if(strcmp(ssld->name, name3)==0)
			break;
	if(!ssld)
	{
		if((ssld = (struct SSLD*)malloc(sizeof(struct SSLD)))==NULL)
		{
			fprintf(stderr,"malloc SSLD error\n");
			exit(-1);
		}
		memset(ssld,0,sizeof(struct SSLD));
		strcpy(ssld->name, name3);
		ssld->next = sld->ssld;
		sld->ssld = ssld;
	}
	ssld->cnt++;
}

void DecodeDNS(u_char *pkt, int len)
{
	//DNSHdr *dnsh;
	//dnsh = (DNSHdr *)pkt;
	u_int qlen,cnt;
	qlen = len - 12;
	u_char *quest;
	u_char dname[qlen];

	quest = pkt + 12;
	u_short i = 0;
	//PrintNetData(stdout,(char *)quest, len);
	while(cnt=(int)(*quest))
	{
		for(cnt; cnt >0; cnt--)
		{
			quest ++;
			dname[i++] = *quest;
		}
		quest++;
		dname[i++]='.';
	}
	dname[i-1]='\0';
	//fprintf(stdout,"Src ip:%s\tURL: %s\n",pip.saddr,dname);
	RecordDomainName(inet_addr(pip.saddr),dname);
	if((++pcnt)==100)
	{//print once every 100 requests
		printf("|----------------------------|\n");
		PrintDNlist(2);
		pcnt = 0;
	}
}

void DecodeUDP(u_char *pkt, int len)
{
   UDPHdr *udph;

   udph = (UDPHdr *) pkt;
#ifdef DEBUG
   printf("UDP header starts at: %p\n", udph);
#endif

   pip.sport = ntohs(udph->uh_sport);
   pip.dport = ntohs(udph->uh_dport);

   pip.udp_len = ntohs(udph->uh_len);

   if(pip.dport==53)
   {
   	pktidx = pktidx +8;
   	//fprintf(stdout,"dns packet, dns pkt len=%d\n",len-8);
   	//PrintNetData(stdout,(char *)pktidx, len-8);
   	DecodeDNS(pktidx, len-8);
   }
   SetFlow();

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_UDP);

      if(pv.data_flag)
         PrintNetData(stdout, (char *) pkt + 8, len-8);
   }

   if(pv.log_flag)
   {
      OpenLogFile();

      PrintIPPkt(log_ptr, IPPROTO_UDP);

      if(pv.data_flag)
         PrintNetData(log_ptr, (char *) pkt + 8, len-8);

      fclose(log_ptr);
   }
}



void DecodeICMP(u_char *pkt, int len)
{
   ICMPHdr *icmph;

   icmph = (ICMPHdr *) pkt;

#ifdef DEBUG
   printf("ICMP type: %d   code: %d\n", icmph->code, icmph->type);
#endif

   switch(icmph->type)
   {
      case ICMP_ECHOREPLY:
                         sprintf(pip.icmp_str, "ECHO REPLY");
                         break;

      case ICMP_DEST_UNREACH:
                switch(icmph->code)
                {
                   case ICMP_NET_UNREACH:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:NET UNREACHABLE");
                            break;

                   case ICMP_HOST_UNREACH:
                            sprintf(pip.icmp_str,  
                                    "UNREACHABLE:HOST UNREACHABLE");
                            break;

                   case ICMP_PROT_UNREACH:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:PROTOCOL UNREACHABLE");
                            break;

                   case ICMP_PORT_UNREACH:
                            sprintf(pip.icmp_str,  
                                    "UNREACHABLE:PORT UNREACHABLE");
                            break;

                   case ICMP_FRAG_NEEDED:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:FRAGMENTATION NEEDED");
                            break;

                   case ICMP_SR_FAILED:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:SOURCE ROUTE FAILED");
                            break;

                   case ICMP_NET_UNKNOWN:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:NETWORK UNKNOWN");
                            break;

                   case ICMP_HOST_UNKNOWN:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:HOST UNKNOWN");
                            break;

                   case ICMP_HOST_ISOLATED:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:HOST ISOLATED");
                            break;

                   case ICMP_NET_ANO:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:NET ANO");
                            break;

                   case ICMP_HOST_ANO:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:HOST ANO");
                            break;

                   case ICMP_NET_UNR_TOS:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:NET UNR TOS");
                            break;

                   case ICMP_HOST_UNR_TOS:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:HOST UNR TOS");
                            break;

                   case ICMP_PKT_FILTERED:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:PACKET FILTERED");
                            break;

                   case ICMP_PREC_VIOLATION:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:PRECEDENCE VIOLATION");
                            break;

                  case ICMP_PREC_CUTOFF:
                            sprintf(pip.icmp_str, 
                                    "UNREACHABLE:PRECEDENCE CUTOFF");
                            break;
               }
               break;

      case ICMP_SOURCE_QUENCH:
                         sprintf(pip.icmp_str, "SOURCE QUENCH");
                         break;

      case ICMP_REDIRECT:
                         sprintf(pip.icmp_str, "REDIRECT");
                         break;

      case ICMP_ECHO:
                         sprintf(pip.icmp_str, "ECHO");
                         break;

      case ICMP_TIME_EXCEEDED:
                         sprintf(pip.icmp_str, "TTL EXCEEDED");
                         break;

      case ICMP_PARAMETERPROB:
                         sprintf(pip.icmp_str, "PARAMETER PROBLEM");
                         break;

      case ICMP_TIMESTAMP:
                         sprintf(pip.icmp_str, "TIMESTAMP");
                         break;

      case ICMP_TIMESTAMPREPLY:
                         sprintf(pip.icmp_str, "TIMESTAMP REPLY");
                         break;

      case ICMP_INFO_REQUEST:
                         sprintf(pip.icmp_str, "INFO REQUEST");
                         break;

      case ICMP_INFO_REPLY:
                         sprintf(pip.icmp_str, "INFO REPLY");
                         break;

      case ICMP_ADDRESS:
                         sprintf(pip.icmp_str, "ADDRESS");
                         break;

      case ICMP_ADDRESSREPLY:
                         sprintf(pip.icmp_str, "ADDRESS REPLY");
                         break;
   }

   SetFlow();

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_ICMP);

      if(pv.data_flag)
         PrintNetData(stdout, (char *) pkt + 4, len-4);
   }

   if(pv.log_flag)
   {
      OpenLogFile();

      PrintIPPkt(log_ptr, IPPROTO_ICMP);
      
      if(pv.data_flag)
         PrintNetData(log_ptr, (char *) pkt + 4, len-4);

      fclose(log_ptr);
   }

   return;
}



void PrintIPPkt(FILE *fp, int type)
{
#ifdef DEBUG
   printf("PrintIPPkt type = %d\n", type);
#endif

   switch(type)
   {
      case IPPROTO_TCP:
                if(flow == RIGHT)
                {
                   fprintf(fp, "%s: %s %s:%d -> %s:%d ", pip.timestamp,
                           pip.proto,pip.saddr, pip.sport, pip.daddr, 
                           pip.dport);
                }
                else
                {
                   fprintf(fp, "%s: %s %s:%d <- %s:%d ", pip.timestamp,
                           pip.proto,pip.daddr, pip.dport, pip.saddr, 
                           pip.sport);
                }

                if(pip.flags & TH_SYN) fprintf(fp, "S"); else fprintf(fp, "*");
                if(pip.flags & TH_FIN) fprintf(fp, "F"); else fprintf(fp, "*");
                if(pip.flags & TH_RST) fprintf(fp, "R"); else fprintf(fp, "*");
                if(pip.flags & TH_PUSH) fprintf(fp, "P"); else fprintf(fp, "*");
                if(pip.flags & TH_ACK) fprintf(fp, "A"); else fprintf(fp, "*");
                if(pip.flags & TH_URG) fprintf(fp, "U"); else fprintf(fp, "*");

                fprintf(fp, "\n");

                fprintf(fp, "        %lX:%lX win=%lX TTL=%d\n",pip.seq, pip.ack,
                        pip.win, pip.ttl);
                break;

      case IPPROTO_UDP:
                if(flow == RIGHT)
                {
                   fprintf(fp, "%s: %s %s.%d -> %s.%d len=%d TTL=%d\n",
                           pip.timestamp, pip.proto, pip.saddr, pip.sport, 
                           pip.daddr, pip.dport, pip.udp_len, pip.ttl);
                }
                else
                {
                   fprintf(fp, "%s: %s %s:%d <- %s:%d len=%d TTL=%d\n",
                           pip.timestamp, pip.proto, pip.daddr, pip.dport,
                           pip.saddr, pip.sport, pip.udp_len, pip.ttl);
                }

                break;

      case IPPROTO_ICMP:
                if(flow == RIGHT)
                {
                   fprintf(fp, "%s: %s %s -> %s TTL=%d %s\n", pip.timestamp, 
                           pip.proto, pip.saddr, pip.daddr, pip.ttl, 
                           pip.icmp_str);
                }
                else
                {
                   fprintf(fp, "%s: %s %s <- %s TTL=%d %s\n", pip.timestamp,
                           pip.proto, pip.daddr, pip.saddr, pip.ttl, 
                           pip.icmp_str);
                }
                break;
   }
}

void PrintNetData(FILE *fp, char *start, int len)
{
   char *end;
   char hexbuf[STD_BUF];
   char charbuf[STD_BUF];
   int col;
   int i;


   end = start + len;

   do
   {
      col = 0;
      bzero(hexbuf,STD_BUF);
      bzero(charbuf,STD_BUF);

      for(i=0;i<16;i++)
      {
         if(start < end)
         {
            sprintf(hexbuf+(i*3),"%.2X ",start[0] & 0xFF);

            if(*start > 0x1F && *start < 0x7E)
            {
               sprintf(charbuf+i+col,"%c",start[0]);
            }
            else
            {
               sprintf(charbuf+i+col, ".");
            }
            start++;
         }
      }

      fprintf(fp,"     %-48s %s\n",hexbuf,charbuf);
      fflush(fp);

   }while(start < end);

   return;
}



void DecodeARP(u_char *pkt, int len, int caplen)
{
   EtherARP *arph;
   char timebuf[64];
   struct in_addr saddr;
   struct in_addr daddr;
   char type[32];

   arph = (EtherARP *) pkt;

   if(len < sizeof(EtherARP))
   {
      printf("Truncated packet\n");
      return;
   }

   GetTime(timebuf);
   memcpy((void *) &saddr, (void *) &arph->arp_spa, sizeof (struct in_addr));
   memcpy((void *) &daddr, (void *) &arph->arp_tpa, sizeof (struct in_addr));

   switch (ntohs(arph->ea_hdr.ar_op))
   { 
      case ARPOP_REQUEST:
                  sprintf(type, "ARP request");
                  break;

      case ARPOP_REPLY:
                  sprintf(type, "ARP reply");
                  break;

      case ARPOP_RREQUEST:
                  sprintf(type, "RARP request");
                  break;

      case ARPOP_RREPLY:
                  sprintf(type, "RARP reply");
                  break;

      default:
                 sprintf(type, "unknown");
                 return;
   }

   if(pv.verbose_flag)
   {
      memcpy((void *) &saddr, (void *) &arph->arp_spa, sizeof (struct in_addr));
      fprintf(stdout, "%s: %s %s", timebuf, "ARP", inet_ntoa(saddr));
      memcpy((void *) &daddr, (void *) &arph->arp_tpa, sizeof (struct in_addr));
      fprintf(stdout, " -> %s  %s\n", inet_ntoa(daddr), type);
   }

   return;
}


void DecodeIPX(u_char *pkt, int len)
{
   printf("IPX packet\n");

   return;
}



void GetTime(char *timebuf)
{
   time_t curr_time;
   struct tm *loc_time;

   curr_time = time(NULL);
   loc_time = localtime(&curr_time);
   strftime(timebuf,STD_BUF-1,"%m/%d/%y[%H.%M.%S]",loc_time);
}



/*----------------------------------------------------------------------------
 *
 * copy_argv()
 *
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 * Lifted from tcpdump.
 *
 *----------------------------------------------------------------------------
 */

char *copy_argv(char **argv)
{
  char **p;
  u_int len = 0;
  char *buf;
  char *src, *dst;
  void ftlerr(char *, ...);

  p = argv;
  if (*p == 0) return 0;

  while (*p)
    len += strlen(*p++) + 1;

  buf = (char *) malloc (len);
  if(buf == NULL)
  {
     fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
     exit(0);
  }
  p = argv;
  dst = buf;
  while ((src = *p++) != NULL)
    {
      while ((*dst++ = *src++) != '\0');
      dst[-1] = ' ';
    }
  dst[-1] = '\0';

  return buf;
}



void SetFlow()
{
   u_long testaddr1;
   u_long testaddr2;
   struct in_addr sin;
   struct in_addr din;

   if(((sin.s_addr = inet_addr(pip.saddr)) == -1)||
      ((din.s_addr = inet_addr(pip.daddr)) == -1))
   {
      //fprintf(stderr,"ERROR: SetFlow() problem doing address conversion\n");
      //fprintf(stderr,"error sip=%s, dip=%s\n",pip.saddr,pip.daddr);
     // CleanExit();
   }
   else
   {
      testaddr1 = ((u_long)sin.s_addr & NETMASK);
      testaddr2 = ((u_long)din.s_addr & NETMASK);

      if(testaddr1 == testaddr2)
      {
         if(sin.s_addr <= din.s_addr)
            flow = RIGHT;
         else
            flow = LEFT;

         return;
      }


#ifdef DEBUG
      printf("source address = %lX  homenet = %lX\n", testaddr1, pv.homenet);
#endif

      if(testaddr1 == pv.homenet)
      {
         if(testaddr2 != pv.homenet)
            flow = LEFT;
         else
            flow = RIGHT; 
      }
      else
      {
         flow = RIGHT;
      }
   }
}





int OpenLogFile()
{
   char log_path[STD_BUF];
   char log_file[STD_BUF];
   char timebuf[STD_BUF];
   char proto[5];


   bzero(log_path, STD_BUF);
   bzero(log_file, STD_BUF);
   bzero(timebuf, STD_BUF);
   bzero(proto, 5);

   if(flow == LEFT)
   {
      sprintf(log_path, "%s/%s", pv.log_dir, pip.daddr);
   }
   else
   {
      sprintf(log_path, "%s/%s", pv.log_dir, pip.saddr);
   }   

#ifdef DEBUG
   fprintf(stderr, "Creating directory: %s\n",log_path);
#endif

   if(mkdir(log_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
   {
#ifdef DEBUG
      if(errno != EEXIST)
      {
         printf("Problem creating directory %s\n",log_path);
      }
#endif
   }

#ifdef DEBUG
   printf("Directory Created!\n");
#endif

   if((!strcasecmp(pip.proto, "TCP"))||
      (!strcasecmp(pip.proto, "UDP")))
   {
      if(pip.sport >= pip.dport)
      {
         sprintf(log_file, "%s/%s:%d-%d", log_path, pip.proto, pip.sport, 
                 pip.dport);
      }
      else
      {
         sprintf(log_file, "%s/%s:%d-%d", log_path, pip.proto, pip.dport, 
                 pip.sport);
      }
   }
   else
   {
      sprintf(log_file, "%s/%s", log_path, pip.proto);
   }   

#ifdef DEBUG
   printf("Opening file: %s\n", log_file);
#endif

   if((log_ptr = fopen(log_file, "a")) == NULL)
   {
       fprintf(stderr, "ERROR: OpenLogFile() => fopen() log file: %s\n", 
               strerror(errno));
       exit(1);
   }

#ifdef DEBUG
   printf("File opened...\n");
#endif

   return 0;
}

