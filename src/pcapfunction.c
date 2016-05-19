#include"pcapfunction.h"
#include"sniffer.h"

enum {
	COL_NO = 0,
	COL_TIME,
	COL_SRC,
	COL_DST,
	COL_PRO,
	COL_LEN,
	COL_SUMMARY,
	LIST_NUM_COLS
};

struct packet_info *phead = NULL;

struct simple_packet {
	char src_ip[42];
	char dst_ip[42];	//大小为40,是为了存储ipv6
	char protocol[16];
	u_int len;
	char summary[100];
} spacket;

/*
* 列出所有可用网卡
*/
int find_interfaces(int *n)
{
	int ret, k;
	pcap_if_t *alldevsp;
	char errbuf[PCAP_ERRBUF_SIZE];

	ret = pcap_findalldevs(&alldevsp, errbuf);
	if (ret == -1) {
		printf("find interface error\n");
		return -1;
	} else {
		for (k = 0; alldevsp; alldevsp = alldevsp->next) {
			if (strstr(alldevsp->name, "eth") > 0
			    || strstr(alldevsp->name, "wlan") > 0) {
				//printf("interface name: %s \n", alldevsp->name);
				sprintf(ifdev[k], "%s", alldevsp->name);
				k++;
			}

		}
	}
	*n = k;
	pcap_freealldevs(alldevsp);
	return 0;
}

////////////packet analysis function////////////////

void tcp_callback(u_char * arg, const struct pcap_pkthdr *pkthdr,
	     const u_char * packet)
{
	tcpn++;
	struct tcp_header *hdr;
	hdr = (struct tcp_header *)(packet + 14 + 20);

	u_short src_port;
	u_short dst_port;
	u_int seq;
	u_int ack;
	src_port = ntohs(hdr->src_port);
	dst_port = ntohs(hdr->dst_port);
	seq = ntohl(hdr->tcp_seq);
	ack = ntohl(hdr->tcp_ack);

	if (src_port == 80 || dst_port == 80)
		strcpy(spacket.protocol, "HTTP");
	else
		strcpy(spacket.protocol, "TCP");
	sprintf(spacket.summary, "DstPort=%u, SrcPort=%u, Seq=%u, Ack=%u",
		dst_port, src_port, seq, ack);
}

void udp_callback(u_char * arg, const struct pcap_pkthdr *pkthdr,
		  const u_char * packet)
{
	udpn++;
	struct udp_header *hdr;
	u_short src_port;
	u_short dst_port;
	u_short len;
	hdr = (struct udp_header *)(packet + 14 + 20);

	src_port = ntohs(hdr->src_port);
	dst_port = ntohs(hdr->dst_port);
	len = ntohs(hdr->len);

	sprintf(spacket.protocol, "UDP");
	sprintf(spacket.summary, "DstPort=%u, SrcPort=%u, Datagram Length=%u",
		dst_port, src_port, len);
}

void icmp_callback(u_char * arg, const struct pcap_pkthdr *pkthdr,
		   const u_char * packet)
{
	icmpn++;
	struct icmp_header *hdr;
	hdr = (struct icmp_header *)(packet + 14 + 20);

	switch (hdr->icmp_type) {
	case 8:
		strcpy(spacket.summary, "ICMP Echo Request");
		break;
	case 0:
		strcpy(spacket.summary, "ICMP Echo Reply");
		break;
	case 3:
		strcpy(spacket.summary, "ICMP Unreachable");
		break;
	case 4:
		strcpy(spacket.summary, "Source quench 源抑制");
		break;
	case 5:
		strcpy(spacket.summary, "ICMP Redirect 重定向");
		break;
	case 9:
		strcpy(spacket.summary, "Router Advertisement");
		break;
	case 10:
		strcpy(spacket.summary, "Router Solicitation");
		break;
	case 11:
		strcpy(spacket.summary, "Time Exceeded");
		break;
	case 13:
		strcpy(spacket.summary, "ICMP Timestamp Request");
		break;
	case 14:
		strcpy(spacket.summary, "ICMP Timestamp Reply");
		break;
	case 17:
		strcpy(spacket.summary, "Address Mask Request");
		break;
	case 18:
		strcpy(spacket.summary, "Address Mask Reply");
		break;
	default:
		break;
	}
	sprintf(spacket.protocol, "%s", "ICMPv4");
}

void ipv6_callback(u_char * arg, const struct pcap_pkthdr *pkthdr,
		   const u_char * packet)
{
	struct ipv6_header *hdr;
	char src[50], dst[50], stemp[5], dtemp[5];
	int i;

	hdr = (struct ipv6_header *)(packet + 14);
	zero(src);
	zero(dst);
	for (i = 1; i <= 16; i++) {
		if (i % 2 == 0 && i < 16) {
			sprintf(stemp, "%02x:", hdr->src_ipv6[i - 1]);
			sprintf(dtemp, "%02x:", hdr->dst_ipv6[i - 1]);
		} else {
			sprintf(stemp, "%02x", hdr->src_ipv6[i - 1]);
			sprintf(dtemp, "%02x", hdr->dst_ipv6[i - 1]);
		}
		strcat(src, stemp);
		strcat(dst, dtemp);
	}
	sprintf(spacket.src_ip, "%s", src);
	sprintf(spacket.dst_ip, "%s", dst);
	sprintf(spacket.protocol, "IPv6");
}

void ip_callback(u_char * arg, const struct pcap_pkthdr *pkthdr,
		 const u_char * packet)
{
	ipn++;
	struct ip_header *hdr;
	hdr = (struct ip_header *)(packet + 14);

	sprintf(spacket.protocol, "%s", "IP");
	sprintf(spacket.src_ip, "%s", inet_ntoa(hdr->src_addr));
	sprintf(spacket.dst_ip, "%s", inet_ntoa(hdr->dst_addr));

	switch (hdr->protocol) {
	case 6:
		tcp_callback(arg, pkthdr, packet);
		break;
	case 17:
		udp_callback(arg, pkthdr, packet);
		break;
	case 1:
		icmp_callback(arg, pkthdr, packet);
		break;
	default:
		break;
	}
}

void arp_callback(u_char * arg, const struct pcap_pkthdr *pkthdr,
		  const u_char * packet)
{
	struct arp_header *hdr;
	u_short oper;
	char src_mac[20];
	char str[5];
	int i;

	arpn++;
	hdr = (struct arp_header *)(packet + 14);
	oper = ntohs(hdr->oper);
	zero(src_mac);

	for (i = 0; i < 6; i++) {
		sprintf(str, "%02X:", hdr->sha[i]);
		if (i == 5)
			sprintf(str, "%02X", hdr->sha[i]);
		strcat(src_mac, str);
	}

	for (i = 0; i < 4; i++) {
		if (3 == i)
			sprintf(str, "%d", hdr->spa[i]);
		else
			sprintf(str, "%d.", hdr->spa[i]);
		strcat(spacket.src_ip, str);
	}

	for (i = 0; i < 4; i++) {
		if (3 == i)
			sprintf(str, "%d", hdr->tpa[i]);
		else
			sprintf(str, "%d.", hdr->tpa[i]);
		strcat(spacket.dst_ip, str);
	}

	if (1 == oper) {
		sprintf(spacket.summary, "who has %s ? tell %s", spacket.dst_ip,
			spacket.src_ip);
	} else if (2 == oper) {
		sprintf(spacket.summary, "%s 's MAC Address is %s",
			spacket.src_ip, src_mac);
	}
	strcpy(spacket.protocol, "ARP");
}

void ether_callback(u_char * arg, const struct pcap_pkthdr *pkthdr,
		    const u_char * packet)
{
	static int packet_num = 0;
	struct ether_header *hdr;
	u_short eth_type;
	char time_str[100];
	char timenow[64];
	char nostr[16];

	packet_num++;
	alln++;

	//zero(spacket.src_ip);
	//zero(spacket.dst_ip);
	//zero(spacket.protocol);
	//zero(spacket.summary);
	zero((char*)&spacket);

	spacket.len = pkthdr->caplen;	//单位是字节

	hdr = (struct ether_header *)packet;
	eth_type = ntohs(hdr->ether_type);

	if (eth_type == 0x0800 || eth_type == 0x0806 || eth_type == 0x86dd) {
		//dump to a cap file
		pcap_dump((u_char *)pcapfp, pkthdr, packet);

		switch (eth_type) {
		case 0x0800:
			ip_callback(arg, pkthdr, packet);
			break;
		case 0x0806:
			arp_callback(arg, pkthdr, packet);
			break;
		case 0x86dd:
			ipv6_callback(arg, pkthdr, packet);
			break;
		default:
			return;
		}
	}
	else {
		return;
	}

	/*时间转换，struct timeval中的 tv_sec, long类型, 也就是time_t */
	sprintf(timenow, "%s", asctime(localtime(&pkthdr->ts.tv_sec)));
	/*从输入参数的包头结构体指针pkthdr获取捕获时间 */
	sprintf(time_str, "%s (%06ld)", timenow, (long)pkthdr->ts.tv_usec);

	sprintf(nostr, "%d", packet_num);

	/*显示在视图treeview_overall中 */
	GtkWidget *overall_view =
	    GTK_WIDGET(gtk_builder_get_object(builder, "treeview_overall"));
	GtkTreeModel *model =
	    gtk_tree_view_get_model(GTK_TREE_VIEW(overall_view));
	GtkListStore *store = GTK_LIST_STORE(model);
	GtkTreeIter iter;
	gtk_list_store_append(store, &iter);
	if (gtk_list_store_iter_is_valid(store, &iter)) {
		gtk_list_store_set(store, &iter, COL_NO, nostr, COL_TIME,
				   time_str, COL_SRC, spacket.src_ip, COL_DST,
				   spacket.dst_ip, COL_PRO, spacket.protocol,
				   COL_LEN, spacket.len, COL_SUMMARY,
				   spacket.summary, -1);
	}
}

/*
* capture packet function
*/
void packet_capture()
{
	pcap_t *handle;
	char error_content[PCAP_ERRBUF_SIZE];

	struct bpf_program bpf_filter;
	bpf_u_int32 net_mask;
	bpf_u_int32 net_ip;

	pcap_lookupnet(select_dev, &net_ip, &net_mask, error_content);

	handle = pcap_open_live(select_dev, BUFSIZ, 1, 0, error_content);

	pcap_compile(handle, &bpf_filter, bpf_filter_str, 0, net_ip);

	pcap_setfilter(handle, &bpf_filter);

	if (pcap_datalink(handle) != DLT_EN10MB)
		return;
	/*initial all the statistics number */
	arpn = icmpn = udpn = tcpn = ipn = alln = 0;
	/*open dump file */
	pcapfp = pcap_dump_open(handle, DUMPFILE);
	/* capture pkt loop */
	pcap_loop(handle, -1, ether_callback, NULL);

	pcap_close(handle);
}
