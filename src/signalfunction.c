#include"sniffer.h"
#include"pcapfunction.h"

extern struct packet_info *phead;

char *packet_list[] =
    { "编号", "捕获时间", "源主机", "目标主机", "协议", "长度",
	"详细信息"
};

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
/* 
* edit the packet_list_view 
*/
void edit_packet_list_view(GtkWidget * view)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkListStore *store;
	GtkTreeModel *model;

	int i;
	for (i = 0; i < LIST_NUM_COLS; i++) {
		renderer = gtk_cell_renderer_text_new();
		gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
							    -1,
							    packet_list[i],
							    renderer,
							    "text", i, NULL);
		//设置列expandable                                       
		col = gtk_tree_view_get_column(GTK_TREE_VIEW(view), i);
		gtk_tree_view_column_set_resizable(col, TRUE);	//可以拖拉改变列宽度
		//gtk_tree_view_column_set_max_width(col, 200);
		//gtk_tree_view_column_set_expand(col, TRUE);
	}

	store =
	    gtk_list_store_new(LIST_NUM_COLS, G_TYPE_STRING, G_TYPE_STRING,
			       G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			       G_TYPE_UINT, G_TYPE_STRING);
	model = GTK_TREE_MODEL(store);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);	/* destroy model automatically with view */

}

/*****************************************************
*菜单中选择网卡菜单项的 相关信号操作
*****************************************************/

/*
 * edit the interface_list_view in if_window
 */
void edit_interface_list_view(GtkWidget * view, int if_num)
{
	GtkCellRenderer *renderer;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreeStore *interface_store;

	int i;
	int if_list_col_num = 2;
	char *if_list_name[] = { "No.", "Interface" };
	for (i = 0; i < if_list_col_num; i++) {
		renderer = gtk_cell_renderer_text_new();
		gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
							    -1,
							    if_list_name[i],
							    renderer,
							    "text", i, NULL);
	}

	interface_store =
	    gtk_tree_store_new(if_list_col_num, G_TYPE_UINT, G_TYPE_STRING);

	for (i = 0; i < if_num; i++) {
		gtk_tree_store_append(interface_store, &iter, NULL);
		gtk_tree_store_set(interface_store, &iter, 0, i + 1, 1,
				   ifdev[i], -1);
	}
	model = GTK_TREE_MODEL(interface_store);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);	/* destroy model automatically with view */

}

/*
 * menu item
 */
void on_imagemenuitem_interface_activate(GtkMenuItem * menuitem,
				    GtkWidget * if_window)
{

	int ret;
	int if_num;
	// char if_list[10][10];
	ret = find_interfaces(&if_num);
	if (ret == 0) {
		GtkWidget *if_treeview =
		    GTK_WIDGET(gtk_builder_get_object
			       (builder, "treeview_interface"));
		edit_interface_list_view(if_treeview, if_num);

		gtk_widget_show(if_window);
	} else {
		GtkWidget *fail_dialog =
		    gtk_message_dialog_new(NULL, GTK_RESPONSE_OK,
					   GTK_MESSAGE_OTHER, GTK_BUTTONS_OK,
					   NULL);
		gtk_message_dialog_set_markup((GtkMessageDialog *) fail_dialog,
					      "<span foreground=\"red\" size=\"x-large\">:) find interfaces fail!</span>");
		gtk_window_set_title(GTK_WINDOW(fail_dialog), "interface info");
		gtk_dialog_run((GtkDialog *) fail_dialog);	// show the dialog
		gtk_widget_destroy(fail_dialog);
	}
}

/*
 * 双击行产生的信号灯select interfaces
 */
void on_treeview_interface_row_activated(GtkTreeView * view,
				    GtkTreePath * path,
				    GtkTreeViewColumn * col, gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	model = gtk_tree_view_get_model(view);

	if (gtk_tree_model_get_iter(model, &iter, path)) {
		gchar *name;
		gtk_tree_model_get(model, &iter, 1, &name, -1);
		g_print("you have double-clicked the row of %s\n", name);
		strcpy(select_dev, name);
		g_free(name);
	}
}

/*
 * apply-button of if_window
 */
void on_button_if_apply_clicked(GtkWidget * gw, GtkTreeView * view)
{

	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter selected_row;

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));

	g_assert(gtk_tree_selection_get_mode(sel) == GTK_SELECTION_SINGLE);

	if (gtk_tree_selection_get_selected(sel, &model, &selected_row)) {
		// gtk_list_store_remove(GTK_LIST_STORE(model), &selected_row);
		gchar *name;
		gtk_tree_model_get(model, &selected_row, 1, &name, -1);
		g_print("Apply, you have selected the row of %s\n", name);
		strcpy(select_dev, name);

		g_free(name);
	} else {
		/*
		 * If no row is selected, the button should not be clickable in
		 * the first place 
		 */
		g_assert_not_reached();
	}
}

/*
 * cancel-button of if_window
 */
void on_button_if_cancel_clicked(GtkWidget * gw, GtkTreeView * view)
{
	GtkTreeViewColumn *col;
	col = gtk_tree_view_get_column(view, 0);
	gtk_tree_view_remove_column(view, col);
	// 删除完第1列后,原来的第
	// 2列也成了第一列，所以两个都是删除 0 列
	col = gtk_tree_view_get_column(view, 0);
	gtk_tree_view_remove_column(view, col);

}

/*
 * 点击if_window窗口左上角的关闭时
 */
void on_if_window_delete_event(GtkWidget * gw, gpointer data)
{

	GtkTreeView *if_view;
	if_view =
	    GTK_TREE_VIEW(gtk_builder_get_object
			  (builder, "treeview_interface"));

	GtkTreeViewColumn *col;
	col = gtk_tree_view_get_column(if_view, 0);
	gtk_tree_view_remove_column(if_view, col);
	col = gtk_tree_view_get_column(if_view, 0);
	gtk_tree_view_remove_column(if_view, col);

	gtk_widget_hide(gw);
}

/*****************************************************
*菜单中 统计 相关信号操作
*****************************************************/
void on_imagemenuitem_statistics_activate(GtkMenuItem * menuitem,
					  GtkWindow * stat_window)
{
	gtk_widget_show(GTK_WIDGET(stat_window));
	GtkWidget *arps_entry, *icmps_entry, *udps_entry, *tcps_entry,
	    *ips_entry, *all_entry;
	char arps[10], icmps[10], udps[10], tcps[10], ips[10], all[10];

	sprintf(arps, "%d", arpn);
	sprintf(icmps, "%d", icmpn);
	sprintf(udps, "%d", udpn);
	sprintf(tcps, "%d", tcpn);
	sprintf(ips, "%d", ipn);
	sprintf(all, "%d", alln);
	arps_entry = GTK_WIDGET(gtk_builder_get_object(builder, "arps_entry"));
	icmps_entry =
	    GTK_WIDGET(gtk_builder_get_object(builder, "icmps_entry"));
	udps_entry = GTK_WIDGET(gtk_builder_get_object(builder, "udps_entry"));
	tcps_entry = GTK_WIDGET(gtk_builder_get_object(builder, "tcps_entry"));
	ips_entry = GTK_WIDGET(gtk_builder_get_object(builder, "ips_entry"));
	all_entry = GTK_WIDGET(gtk_builder_get_object(builder, "all_entry"));
	/*show in the graphical interface */
	gtk_entry_set_text((GtkEntry *) arps_entry, arps);
	gtk_entry_set_text((GtkEntry *) icmps_entry, icmps);
	gtk_entry_set_text((GtkEntry *) udps_entry, udps);
	gtk_entry_set_text((GtkEntry *) tcps_entry, tcps);
	gtk_entry_set_text((GtkEntry *) ips_entry, ips);
	gtk_entry_set_text((GtkEntry *) all_entry, all);
}

/*****************************************************
*菜单中设置过滤菜单项的 相关信号操作
*****************************************************/
void on_imagemenuitem_filter_activate(GtkMenuItem * menuitem,
				      GtkWindow * if_window)
{
	gtk_widget_show(GTK_WIDGET(if_window));
}

void on_imagemenuitem_about_activate(GtkMenuItem * menuitem,
				     GtkDialog * about_dialog)
{
	gtk_widget_show(GTK_WIDGET(about_dialog));
}

/*
 * apply button
 */
void
on_filter_button_apply_clicked(GtkMenuItem * menuitem,
			       GtkWindow * filter_window)
{
	GtkCheckButton *arpbtn, *ipbtn, *tcpbtn, *udpbtn, *icmpbtn, *httpbtn;
	arpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_arp");
	ipbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_ip");
	tcpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_tcp");
	udpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_udp");
	icmpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_icmp");
	httpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_http");

	strcpy(bpf_filter_str, "");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(arpbtn))) {
		strcat(bpf_filter_str, "arp");
		g_print("select arp\n");
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ipbtn))) {
		if (strlen(bpf_filter_str) == 0)
			sprintf(bpf_filter_str, "ip");
		else
			strcat(bpf_filter_str, " or ip");
		g_print("select ip\n");
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tcpbtn))) {
		if (strlen(bpf_filter_str) == 0)
			sprintf(bpf_filter_str, "tcp");
		else
			strcat(bpf_filter_str, " or tcp");
		g_print("select tcp\n");
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(udpbtn))) {
		if (strlen(bpf_filter_str) == 0)
			sprintf(bpf_filter_str, "udp");
		else
			strcat(bpf_filter_str, " or udp");
		g_print("select udp\n");
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(icmpbtn))) {
		if (strlen(bpf_filter_str) == 0)
			sprintf(bpf_filter_str, "icmp");
		else
			strcat(bpf_filter_str, " or icmp");
		g_print("select icmp\n");
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(httpbtn))) {
		if (strlen(bpf_filter_str) == 0)
			sprintf(bpf_filter_str, "http");
		else
			strcat(bpf_filter_str, " or http");
		g_print("select http\n");
	}
}

/*
 * reset button
 */
void
on_filter_button_reset_clicked(GtkMenuItem * menuitem,
			       GtkWindow * filter_window)
{
	GtkCheckButton *arpbtn, *ipbtn, *tcpbtn, *udpbtn, *icmpbtn, *httpbtn;
	arpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_arp");
	ipbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_ip");
	tcpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_tcp");
	udpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_udp");
	icmpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_icmp");
	httpbtn =
	    (GtkCheckButton *) gtk_builder_get_object(builder,
						      "checkbutton_http");

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(arpbtn), FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ipbtn), FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(tcpbtn), FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(udpbtn), FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(icmpbtn), FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(httpbtn), FALSE);

	strcpy(bpf_filter_str, "");

}

/*****************************************************
*主页面 设置过滤规则
*****************************************************/
void on_main_filter_entry_activate(GtkWidget * gw, gpointer data)
{
	GtkEntry *filter_entry;
	filter_entry =
	    GTK_ENTRY(gtk_builder_get_object(builder, "main_filter_entry"));
	gtk_entry_buffer_set_text(gtk_entry_get_buffer(filter_entry), "", 0);
}

void on_main_set_filter_button_clicked(GtkWidget * gw, gpointer data)
{
	GtkEntry *filter_entry;
	const gchar *filter_rule;
	filter_entry =
	    GTK_ENTRY(gtk_builder_get_object(builder, "main_filter_entry"));
	filter_rule =
	    gtk_entry_buffer_get_text(gtk_entry_get_buffer(filter_entry));

	sprintf(bpf_filter_str, "%s", filter_rule);
	/*
	 * 预编译规则，检测书写是否正确
	 */
	pcap_t *handle;
	char error_content[PCAP_ERRBUF_SIZE];
	int ret;
	struct bpf_program bpf_filter;
	bpf_u_int32 net_mask;
	bpf_u_int32 net_ip;

	pcap_lookupnet(select_dev, &net_ip, &net_mask, error_content);
	handle = pcap_open_live("eth0", BUFSIZ, 1, 0, error_content);

	ret = pcap_compile(handle, &bpf_filter, bpf_filter_str, 0, net_ip);
	if (-1 == ret) {
		g_print("%s 不符合规则\n", bpf_filter_str);
		GtkWidget *dialog;
		dialog = gtk_message_dialog_new(NULL, GTK_RESPONSE_OK,
						GTK_MESSAGE_OTHER,
						GTK_BUTTONS_OK, NULL);
		gtk_message_dialog_set_markup((GtkMessageDialog *)
					      dialog,
					      "<span foreground=\"red\" size=\"x-large\">:) 过滤规则书写不正确</span>");
		gtk_window_set_title(GTK_WINDOW(dialog), "Set Filter rule");
		gtk_dialog_run((GtkDialog *) dialog);	// show the dialog
		gtk_widget_destroy(dialog);

	}
}

/*****************************************************
*主页面的开始捕获按键
*****************************************************/
pthread_t capture_tid;
/*
 * start capture
 */
void on_toolbutton_start_clicked(GtkWidget * gw, gpointer data)
{
	g_print("filter rule:%s\n", bpf_filter_str);
	if (strlen(select_dev) == 0) {
		g_print("The program use the default device: eth0\n");
		sprintf(select_dev, "eth0");
	}
	g_print("selected interface:%s\n", select_dev);

	// create thread to capture the packets
	int ret =
	    pthread_create(&capture_tid, NULL, (void *)packet_capture, NULL);

	if (ret != 0) {
		GtkWidget *capture_dialog;
		capture_dialog =
		    gtk_message_dialog_new(NULL, GTK_RESPONSE_OK,
					   GTK_MESSAGE_OTHER, GTK_BUTTONS_OK,
					   NULL);
		gtk_message_dialog_set_markup((GtkMessageDialog *)
					      capture_dialog,
					      "<span foreground=\"red\" size=\"x-large\">:) create thread error!</span>");
		gtk_window_set_title(GTK_WINDOW(capture_dialog),
				     "Start Capture");
		gtk_dialog_run((GtkDialog *) capture_dialog);	// show the dialog
		gtk_widget_destroy(capture_dialog);
		return;
	}
}

/*
 * stop capture
 */
void on_toolbutton_stop_clicked(GtkWidget * gw, gpointer data)
{
	int ret = pthread_cancel(capture_tid);
	if (ret != 0) {
		GtkWidget *stop_dialog;
		stop_dialog =
		    gtk_message_dialog_new(NULL, GTK_RESPONSE_OK,
					   GTK_MESSAGE_OTHER, GTK_BUTTONS_CLOSE,
					   NULL);
		gtk_message_dialog_set_markup((GtkMessageDialog *) stop_dialog,
					      "<span foreground=\"red\" size=\"x-large\">=) cancel fail!</span>");
		gtk_window_set_title(GTK_WINDOW(stop_dialog), "Stop Capture");
		gtk_dialog_run((GtkDialog *) stop_dialog);	// show the dialog
		gtk_widget_destroy(stop_dialog);
	} else
		pcap_dump_close(pcapfp);

}

/*****************************************************
*Treeview_overall中点击某一行时产生的信号
*****************************************************/
/*
 * 在 treeview_single中显示数据包的详细  封装信息
 */
void show_single_packet(int pktno, struct pcap_pkthdr *pkthdr, const u_char * packet)
{
	GtkTreeStore *store;
	GtkTreeIter iter, child, grandchild;
	store = gtk_tree_store_new(1, G_TYPE_STRING);

	int i;
	int j;
/***-----------------------------------------***/
	// frame
	gtk_tree_store_append(store, &iter, NULL);
	char show_str[100];
	sprintf(show_str, "Frame %d, capture length %d bytes", pktno,
		pkthdr->caplen);
	gtk_tree_store_set(store, &iter, 0, show_str, -1);
	for (i = 0; i < 3; i++) {
		gtk_tree_store_append(store, &child, &iter);
		switch (i) {
		case 0:
			sprintf(show_str, "Frame: %d", pktno);
			break;
		case 1:
			sprintf(show_str, "Packet Length: %u", pkthdr->caplen);
			break;
		case 2:
			sprintf(show_str, "Capture Time: %s [%06ld]",
				asctime(localtime(&pkthdr->ts.tv_sec)),
				(long)pkthdr->ts.tv_usec);
			break;
		}
		gtk_tree_store_set(store, &child, 0, show_str, -1);
	}
/***-----------------------------------------***/
	// ethernet
	char ptype[5];
	u_short eth_type;
	struct ether_header *hdr;

	hdr = (struct ether_header *)packet;
	eth_type = ntohs(hdr->ether_type);
	printf("%04x\n", eth_type);
	switch (eth_type) {
	case 0x0800:
		sprintf(ptype, "IP");
		break;
	case 0x0806:
		sprintf(ptype, "ARP");
		break;
	case 0x8035:
		sprintf(ptype, "RARP");
		break;
	case 0x86dd:
		sprintf(ptype, "IPv6");
		break;
	default:
		sprintf(ptype, "%04x", eth_type);
		break;
	}
	char src_mac[25];
	char dst_mac[25];
	sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->src_mac[0],
		hdr->src_mac[1], hdr->src_mac[2], hdr->src_mac[3],
		hdr->src_mac[4], hdr->src_mac[5]);
	sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->dst_mac[0],
		hdr->dst_mac[1], hdr->dst_mac[2], hdr->dst_mac[3],
		hdr->dst_mac[4], hdr->dst_mac[5]);

	gtk_tree_store_append(store, &iter, NULL);
	gtk_tree_store_set(store, &iter, 0, "Ethernet Layer", -1);
	for (i = 0; i < 3; i++) {
		gtk_tree_store_append(store, &child, &iter);
		switch (i) {
		case 0:
			sprintf(show_str, "Source MAC: %s", src_mac);
			break;
		case 1:
			sprintf(show_str, "Destination MAC: %s", dst_mac);
			break;
		case 2:
			sprintf(show_str, "Protocol type: %s", ptype);
			break;
		}
		gtk_tree_store_set(store, &child, 0, show_str, -1);
	}

/***-----------------------------------------***/
	// arp
	char src_ip[20];
	char dst_ip[20];
	if (0x0806 == eth_type) {
		struct arp_header *hdr;

		u_short oper;
		char operation[20];

		hdr = (struct arp_header *)(packet + 14);
		oper = ntohs(hdr->oper);
		switch (oper) {
		case 1:
			sprintf(operation, "ARP Request");
			break;
		case 2:
			sprintf(operation, "ARP Reply");
			break;
		case 3:
			sprintf(operation, "RARP Request");
			break;
		case 4:
			sprintf(operation, "RARP Reply");
			break;
		default:
			break;
		}

		sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->sha[0],
			hdr->sha[1], hdr->sha[2], hdr->sha[3], hdr->sha[4],
			hdr->sha[5]);
		sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->tha[0],
			hdr->tha[1], hdr->tha[2], hdr->tha[3], hdr->tha[4],
			hdr->tha[5]);

		sprintf(src_ip, "%d.%d.%d.%d", hdr->spa[0], hdr->spa[1],
			hdr->spa[2], hdr->spa[3]);
		sprintf(dst_ip, "%d.%d.%d.%d", hdr->tpa[0], hdr->tpa[1],
			hdr->tpa[2], hdr->tpa[3]);

		// store
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0, "ARP", -1);
		for (i = 0; i < 9; i++) {
			gtk_tree_store_append(store, &child, &iter);
			switch (i) {
			case 0:
				sprintf(show_str, "Hardware Type: %d",
					ntohs(hdr->htype));
				break;
			case 1:
				sprintf(show_str, "Protocol Type: %d",
					ntohs(hdr->ptype));
				break;
			case 2:
				sprintf(show_str, "Hardware Length: %d",
					hdr->hlen);
				break;
			case 3:
				sprintf(show_str, "Protocol Length: %d",
					hdr->plen);
				break;
			case 4:
				sprintf(show_str, "Operation: %s", operation);
				break;
			case 5:
				sprintf(show_str, "Sender MAC Address: %s",
					src_mac);
				break;
			case 6:
				sprintf(show_str, "Sender IP Address: %s",
					src_ip);
				break;
			case 7:
				sprintf(show_str, "Target MAC Address: %s",
					dst_mac);
				break;
			case 8:
				sprintf(show_str, "Target IP Address: %s",
					dst_ip);
				break;
			}
			gtk_tree_store_set(store, &child, 0, show_str, -1);
		}
	}
/***-----------------------------------------***/
	// IP 
	u_int8_t tprotocol = 0;	// transmission protocol , tcp or udp
	if (0x0800 == eth_type) {
		struct ip_header *hdr;
		u_int hlen;
		u_int offset;
		u_char tos;
		u_int16_t chksum;
		hdr = (struct ip_header *)(packet + 14);

		chksum = ntohs(hdr->checksum);
		hlen = hdr->ip_hdr_len << 2;
		tos = hdr->tos;
		offset = ntohs(hdr->frag_off);

		tprotocol = hdr->protocol;
		char protocol_str[5];
		switch (hdr->protocol) {
		case 6:
			sprintf(protocol_str, "TCP");
			break;
		case 17:
			sprintf(protocol_str, "UDP");
			break;
		case 1:
			sprintf(protocol_str, "ICMP");
			break;
		default:
			zero(protocol_str);
			break;
		}
		// store
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0,
				   "Internet Protocol Version 4(IPv4)", -1);
		for (i = 0; i < 12; i++) {
			gtk_tree_store_append(store, &child, &iter);
			switch (i) {
			case 0:
				sprintf(show_str, "Version: %d",
					hdr->ip_version);
				break;
			case 1:
				sprintf(show_str, "Header Length: %d", hlen);
				break;
			case 2:
				sprintf(show_str, "TOS: %d", tos);
				break;
			case 3:
				sprintf(show_str, "Total Length: %d",
					ntohs(hdr->tot_len));
				break;
			case 4:
				sprintf(show_str, "Identification: %d",
					ntohs(hdr->id));
				break;
			case 5:
				sprintf(show_str, "Flags: 0x%02X",
					offset & 0xe000);
				gtk_tree_store_set(store, &child, 0, show_str,
						   -1);
				for (j = 0; j < 3; j++) {
					gtk_tree_store_append(store,
							      &grandchild,
							      &child);
					switch (j) {
					case 0:
						sprintf(show_str,
							"%d... .... = Reserved bit",
							(offset & 0x8000) >>
							15);
						break;
					case 1:
						sprintf(show_str,
							".%d.. .... = Don't Fragment",
							(offset & 0x4000) >>
							14);
						break;
					case 2:
						sprintf(show_str,
							"..%d. .... = More Fragments",
							(offset & 0x2000) >>
							13);
						break;
					}
					gtk_tree_store_set(store, &grandchild,
							   0, show_str, -1);
				}
				break;
			case 6:
				sprintf(show_str, "Fragment offset: %d",
					offset & 0x1fff);
				break;
			case 7:
				sprintf(show_str, "Time to live(TTL): %d",
					hdr->ttl);
				break;
			case 8:
				sprintf(show_str,
					"Transimission Protocol: %s(%d)",
					protocol_str, hdr->protocol);
				break;
			case 9:
				sprintf(show_str, "Header Checksum: 0x%x",
					chksum);
				break;
			case 10:
				sprintf(show_str, "Source IP Address: %s",
					inet_ntoa(hdr->src_addr));
				break;
			case 11:
				sprintf(show_str, "Desitination IP Address: %s",
					inet_ntoa(hdr->dst_addr));
				break;
			}
			if (i != 5)
				gtk_tree_store_set(store, &child, 0, show_str,
						   -1);
		}

	}
/***-----------------------------------------***/
	// IPv6
	if (0x86dd == eth_type) {
		struct ipv6_header *hdr;
		hdr = (struct ipv6_header *)(packet + 14);

		char src[50], dst[50], stemp[5], dtemp[5];
		strcpy(src, "");
		strcpy(dst, "");
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

		// store
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0,
				   "Internet Protocol Version 6(IPv6)", -1);
		for (i = 0; i < 8; i++) {
			gtk_tree_store_append(store, &child, &iter);
			switch (i) {
			case 0:
				sprintf(show_str, "Version: %d",
					hdr->ip_version);
				break;
			case 1:
				sprintf(show_str, "Traffic Class: %d",
					(hdr->traffic_class_1 << 4) |
					hdr->traffic_class_2);
				break;
			case 2:
				sprintf(show_str, "Flow Label: %d",
					(hdr->flow_label_1 << 16) |
					ntohs(hdr->flow_label_2));
				break;
			case 3:
				sprintf(show_str, "Payload Length: %d",
					ntohs(hdr->payload_length));
				break;
			case 4:
				sprintf(show_str, "Next Header: %d",
					hdr->next_header);
				break;
			case 5:
				sprintf(show_str, "Hop Limit: %d",
					hdr->hop_limit);
				gtk_tree_store_set(store, &child, 0, show_str,
						   -1);
				break;
			case 6:
				sprintf(show_str, "Source IPv6 Address: %s",
					src);
				break;
			case 7:
				sprintf(show_str,
					"Desitination IPv6 Address: %s", dst);
				break;
			}
			gtk_tree_store_set(store, &child, 0, show_str, -1);
		}
	}
/***-----------------------------------------***/
	int http_flag = 0;
	// TCP
	if (6 == tprotocol) {
		struct tcp_header *hdr;
		u_char flags;
		u_int hlen;
		u_short dst_port;
		u_short src_port;
		char protocol_str[10];	// 应用层协议
		hdr = (struct tcp_header *)(packet + 14 + 20);
		dst_port = ntohs(hdr->dst_port);
		src_port = ntohs(hdr->src_port);
		if (dst_port == 80 || src_port == 80)
			http_flag = 1;
		hlen = hdr->tcp_off << 2;
		flags = hdr->th_flags;

		switch (dst_port) {
		case 80:
			sprintf(protocol_str, "HTTP");
			break;
		case 21:
			sprintf(protocol_str, "FTP");
			break;
		case 23:
			sprintf(protocol_str, "TELNET");
			break;
		case 25:
			sprintf(protocol_str, "SMTP");
			break;
		case 110:
			sprintf(protocol_str, "POP3");
			break;
		default:
			zero(protocol_str);
			break;
		}
		// store
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0,
				   "Transimission Control Protocol(TCP)", -1);
		for (i = 0; i < 9; i++) {
			gtk_tree_store_append(store, &child, &iter);
			switch (i) {
			case 0:
				sprintf(show_str, "Source Port: %d",
					ntohs(hdr->src_port));
				break;
			case 1:
				sprintf(show_str, "Desitination Port: %s(%d)",
					protocol_str, ntohs(hdr->dst_port));
				break;
			case 2:
				sprintf(show_str, "Sequence Number: %u",
					ntohl(hdr->tcp_seq));
				break;
			case 3:
				sprintf(show_str, "Acknowledgement Number: %u",
					ntohl(hdr->tcp_ack));
				break;
			case 4:
				sprintf(show_str, "Header Length: %d bytes",
					hlen);
				break;
			case 5:
				sprintf(show_str, "Flags: 0x%x", flags);
				gtk_tree_store_set(store, &child, 0, show_str,
						   -1);
				for (j = 0; j < 6; j++) {
					gtk_tree_store_append(store,
							      &grandchild,
							      &child);
					switch (j) {
					case 0:
						sprintf(show_str,
							"..%d. .... = URG",
							(0x20 & flags) >> 5);
						break;
					case 1:
						sprintf(show_str,
							"...%d .... = ACK",
							(0x10 & flags) >> 4);
						break;
					case 2:
						sprintf(show_str,
							".... %d... = PSH",
							(0x08 & flags) >> 3);
						break;
					case 3:
						sprintf(show_str,
							".... .%d.. = RST",
							(0x04 & flags) >> 2);
						break;
					case 4:
						sprintf(show_str,
							".... ..%d. = SYN",
							(0x02 & flags) >> 1);
						break;
					case 5:
						sprintf(show_str,
							".... ...%d = FIN",
							0x01 & flags);
						break;
					}
					gtk_tree_store_set(store, &grandchild,
							   0, show_str, -1);
				}
				break;
			case 6:
				sprintf(show_str, "Window size: %d",
					ntohs(hdr->th_win));
				break;
			case 7:
				sprintf(show_str, "Checksum: 0x%x",
					ntohs(hdr->th_sum));
				break;
			case 8:
				sprintf(show_str, "Urgent Pointer: 0x%x",
					ntohs(hdr->th_urp));
				break;

			}
			if (i != 5)
				gtk_tree_store_set(store, &child, 0, show_str,
						   -1);
		}
		if (hlen > 20) {	// 报头有选项数据
			gtk_tree_store_append(store, &child, &iter);
			gtk_tree_store_set(store, &child, 0, "Options", -1);
			const u_char *p = (packet + 14 + 20 + 20);
			u_int mss;
			mss = ntohl((u_int) * p);
			for (j = 0; j < 3; j++) {
				gtk_tree_store_append(store, &grandchild,
						      &child);
				switch (j) {
				case 0:
					sprintf(show_str,
						"Maximum segment: %u bytes",
						mss);
					break;
				case 1:
					sprintf(show_str,
						"TCP SACK Permitted Option:..");
					break;
				case 2:
					sprintf(show_str, "Timestamp:..");
					break;
				}
				gtk_tree_store_set(store, &grandchild, 0,
						   show_str, -1);
			}
		}
		if (pkthdr->caplen > 14 + 20 + hlen && !http_flag) {
			// has data
			gtk_tree_store_append(store, &iter, NULL);
			gtk_tree_store_set(store, &iter, 0, "Data", -1);
		}
	}
/***-----------------------------------------***/
	//http
	if (http_flag) {
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0,
				   "Hypertext Transfer Protocol(HTTP)", -1);
		char http_header[1500];

		memcpy(http_header, (packet + 14 + 20 + 20),
		       pkthdr->caplen - 54);
		/*
		   p = http_header;
		   for (i = 0; i < 3; i++) {
		   gtk_tree_store_append(store, &child, &iter);
		   j=0;
		   while(*p!='\r'&&*(p+1)!='\n')
		   {
		   show_str[j] =(char)*p;
		   j++;
		   p++;
		   }
		   gtk_tree_store_set(store, &child, 0,
		   show_str, -1);
		   p +=2;  

		   } */

	}
/***-----------------------------------------***/
	// UDP
	if (17 == tprotocol) {
		struct udp_header *hdr;
		u_short src_port;
		u_short dst_port;
		u_short len;
		u_short chksum;
		hdr = (struct udp_header *)(packet + 14 + 20);

		src_port = ntohs(hdr->src_port);
		dst_port = ntohs(hdr->dst_port);
		len = ntohs(hdr->len);
		chksum = ntohs(hdr->checksum);

		char protocol_str[64];
		switch (dst_port) {
		case 138:
			sprintf(protocol_str, "NETBIOS Datagram Service");
			break;
		case 137:
			sprintf(protocol_str, "NETBIOS Name Service");
			break;
		case 139:
			sprintf(protocol_str, "NETBIOS session service");
			break;
		case 53:
			sprintf(protocol_str, "Domain Name Service");
			break;
		default:
			break;
		}

		// printf("Length:%d\n", len);
		// printf("Checksum:%d\n", chksum);

		// store
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0,
				   "User Datagram Protocol(UDP)", -1);
		for (i = 0; i < 4; i++) {
			gtk_tree_store_append(store, &child, &iter);
			switch (i) {
			case 0:
				sprintf(show_str, "Source Port: %d", src_port);
				break;
			case 1:
				sprintf(show_str, "Destination Port: %s(%d)",
					protocol_str, dst_port);
				break;
			case 2:
				sprintf(show_str, "Length: %d", len);
				break;
			case 3:
				sprintf(show_str, "Checksum: 0x%x", chksum);
				break;

			}
			gtk_tree_store_set(store, &child, 0, show_str, -1);
		}

		gtk_tree_store_append(store, &iter, NULL);
		sprintf(show_str, "Data (%u bytes)", len);
		gtk_tree_store_set(store, &iter, 0, show_str, -1);
	}
/***-----------------------------------------***/
	// icmp
	if (1 == tprotocol) {
		struct icmp_header *hdr;
		hdr = (struct icmp_header *)(packet + 14 + 20);
		char icmp_type_str[50];
		switch (hdr->icmp_type) {
		case 0:
			sprintf(icmp_type_str, "ICMP Echo Reply Protocol");
			break;
		case 8:
			sprintf(icmp_type_str, "ICMP Echo Request Protocol");
			break;
		case 3:
			sprintf(icmp_type_str, "ICMP Unreachable");
			break;
		case 4:
			sprintf(icmp_type_str, "Source quench 源抑制");
			break;
		case 5:
			sprintf(icmp_type_str, "ICMP Redirect 重定向");
			break;
		case 9:
			sprintf(icmp_type_str, "Router Advertisement");
			break;
		case 10:
			sprintf(icmp_type_str, "Router Solicitation");
			break;
		case 11:
			sprintf(icmp_type_str, "Time Exceeded");
			break;
		case 13:
			sprintf(icmp_type_str, "ICMP Timestamp Request");
			break;
		case 14:
			sprintf(icmp_type_str, "ICMP Timestamp Reply");
			break;
		case 17:
			sprintf(icmp_type_str, "Address Mask Request");
			break;
		case 18:
			sprintf(icmp_type_str, "Address Mask Reply");
			break;
		default:
			break;
		}

		// store
		gtk_tree_store_append(store, &iter, NULL);
		gtk_tree_store_set(store, &iter, 0,
				   "Internet Control Message Protocol(ICMP)",
				   -1);
		for (i = 0; i < 5; i++) {
			gtk_tree_store_append(store, &child, &iter);
			switch (i) {
			case 0:
				sprintf(show_str, "ICMP Type: %s(%d)",
					icmp_type_str, hdr->icmp_type);
				break;
			case 1:
				sprintf(show_str, "ICMP Code: %d",
					hdr->icmp_code);
				break;
			case 2:
				sprintf(show_str, "Checksum: 0x%x",
					ntohs(hdr->icmp_chksum));
				break;
			case 3:
				sprintf(show_str, "Identifier: %d",
					hdr->icmp_id);
				break;
			case 4:
				sprintf(show_str, "Sequence Number: %d",
					hdr->icmp_seq);
				break;
			}
			gtk_tree_store_set(store, &child, 0, show_str, -1);
		}
	}

/************************************/
	// 连接 model and view
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkTreeModel *model;
	GtkTreeView *view;

	view = GTK_TREE_VIEW(gtk_builder_get_object(builder,
						    "treeview_single"));
	// 删除原来的
	col = gtk_tree_view_get_column(view, 0);
	if (col)
		gtk_tree_view_remove_column(view, col);

	model = GTK_TREE_MODEL(store);

	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
						    -1, NULL, renderer, "text",
						    0, NULL);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);	// destroy model automatically with view 

}

/**
* 十六进制显示数据包
*/
void show_raw_packet(u_int caplen, const u_char * packet)
{
	//g_print("show raw packet\n");
	GtkTextView *textview1 =
	    (GtkTextView *) gtk_builder_get_object(builder, "textview1");
	GtkTextView *textview2 =
	    (GtkTextView *) gtk_builder_get_object(builder, "textview2");
	GtkTextView *textview3 =
	    (GtkTextView *) gtk_builder_get_object(builder, "textview3");

	GtkTextBuffer *buffer1 =
	    gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview1));
	GtkTextBuffer *buffer2 =
	    gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview2));
	GtkTextBuffer *buffer3 =
	    gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview3));

	GtkTextIter iter1, iter2, iter3;

	/*gtk_text_buffer_get_bounds(buffer1, &start, &end);
	   gtk_text_buffer_delete(buffer1, &start, &end);
	   gtk_text_buffer_get_bounds(buffer2, &start, &end);
	   gtk_text_buffer_delete(buffer2, &start, &end);
	   gtk_text_buffer_get_bounds(buffer3, &start, &end);
	   gtk_text_buffer_delete(buffer3, &start, &end);
	 */
	/*set empty of buffer */
	gtk_text_buffer_set_text(buffer1, "", -1);
	gtk_text_buffer_set_text(buffer2, "", -1);
	gtk_text_buffer_set_text(buffer3, "", -1);

	gtk_text_buffer_get_iter_at_offset(buffer1, &iter1, 0);
	gtk_text_buffer_get_iter_at_offset(buffer2, &iter2, 0);
	gtk_text_buffer_get_iter_at_offset(buffer3, &iter3, 0);
	char hex[10];
	char str[17];
	u_char ch;
	u_int i, j;
	for (i = 0; i < caplen; i += 16) {
		sprintf(hex, "%04x\n", i);
		// gtk_text_buffer_insert_at_cursor(buffer1, hex, 5);
		gtk_text_buffer_insert(buffer1, &iter1, hex, -1);
		for (j = 0; j < 16; j++) {
			//sprintf(str,"");
			ch = *(packet + i + j);
			sprintf(str, "%02X ", ch);
			// gtk_text_buffer_insert_at_cursor(buffer2, str, 3);
			gtk_text_buffer_insert(buffer2, &iter2, str, -1);
			//sprintf(str,"");
			if (ch < 32 || ch > 126)
				sprintf(str, ".");
			else
				sprintf(str, "%c", ch);
			gtk_text_buffer_insert(buffer3, &iter3, str, -1);

		}
		gtk_text_buffer_insert(buffer2, &iter2, "\n", -1);
		gtk_text_buffer_insert(buffer3, &iter3, "\n", -1);
	}
	if (i - 16 < caplen) {
		int left;
		left = caplen - i + 16;
		i = i - 16;

		sprintf(hex, "%04x\n", i + 16);
		gtk_text_buffer_insert(buffer1, &iter1, hex, -1);

		for (j = 0; j < left; j++) {
			ch = *(packet + i + j);
			sprintf(str, "%02X ", ch);
			gtk_text_buffer_insert(buffer2, &iter2, str, -1);

			if (ch < 32 || ch > 126)
				sprintf(str, ".");
			else
				sprintf(str, "%c", (char)ch);
			gtk_text_buffer_insert(buffer3, &iter3, str, -1);
		}
		//gtk_text_buffer_insert(buffer2, &iter2, "\n", -1);
		//gtk_text_buffer_insert(buffer3, &iter3, "\n", -1);
	}
	//g_print("show raw packet end\n");
}

int pktlen = 0;
/*
* 数据包简略信息显示区域的选中信号，选中后，
* 数据包的详细封装信息显示在treeview_single中
* 十六进制原始信息显示在textview中
*/

void on_treeview_overall_selection_changed(GtkTreeSelection * select,
					   gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;

	if (gtk_tree_selection_get_selected(select, &model, &iter)) {
		// 数据类型有问题，取字符串可以, u_int 类型失败
		gchar *no;
		gtk_tree_model_get(model, &iter, 0, &no, -1);
		u_int packet_no = atoi(no);
		//g_print("you have clicked the row of %d\n", packet_no);

		/*
		 * read from dump cap file
		 */
		char errBuff[PCAP_ERRBUF_SIZE];
		pcap_t *readHandle = pcap_open_offline(DUMPFILE, errBuff);

		if (NULL == readHandle) {
			fprintf(stderr, "Error: %s\n", errBuff);
			return;
		}
		int k = 0;
		int status = 1;
		struct pcap_pkthdr *pkthdr =
		    (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

		const u_char *packet;
		while (k < packet_no && 1 == status) {
			status = pcap_next_ex(readHandle, &pkthdr, &packet);
			k++;
		}
		pcap_close(readHandle);

		u_char *packet_copy =
		    (u_char *) malloc(sizeof(u_char) * (pkthdr->caplen + 2));
		memcpy(packet_copy, packet, pkthdr->caplen);

		show_single_packet(packet_no, pkthdr, packet);
		show_raw_packet(pkthdr->caplen, packet_copy);

		pktlen = pkthdr->caplen;

	} else {
		g_assert_not_reached();
	}
}

/*****************************************************
*Treeview_single中点击某一行时产生的信号
*****************************************************/

struct selectRange {
	int start;
	int end;
} srange;

/*
* 高亮选中十六进制区域
*/
void show_selection_hex(struct selectRange *srange)
{
	g_usleep(1);
	GDK_THREADS_ENTER();
	int start, end;
	start = srange->start;
	end = srange->end;

	GtkTextView *textview2 =
	    (GtkTextView *) gtk_builder_get_object(builder, "textview2");

	GtkTextBuffer *buffer2 = gtk_text_view_get_buffer
	    (GTK_TEXT_VIEW(textview2));

	int line1, line2;
	//printf("start=%d, end=%d\n", start, end);
	line1 = start / 16;
	start = start - 16 * line1;
	start = start * 3;
	line2 = end / 16;
	end = end - 16 * line2;
	end = end * 3;
	//printf("line1=%d, line2=%d, start=%d, end=%d\n", line1, line2, start, end);
	GtkTextIter iter1, iter2;
	/*select textview2 */
	gtk_text_buffer_get_iter_at_line_offset(buffer2, &iter1, line1, start);
	gtk_text_buffer_get_iter_at_line_offset(buffer2, &iter2, line2, end);
	gtk_text_buffer_select_range(buffer2, &iter1, &iter2);

	GDK_THREADS_LEAVE();
}

void show_selection_ascii(struct selectRange *srange)
{
	g_usleep(1);
	GDK_THREADS_ENTER();
	int start, end;
	start = srange->start;
	end = srange->end;

	GtkTextView *textview3 =
	    (GtkTextView *) gtk_builder_get_object(builder, "textview3");

	GtkTextBuffer *buffer3 =
	    gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview3));
	int line1, line2;
	line1 = start / 16;
	start = start - 16 * line1;

	line2 = end / 16;
	end = end - 16 * line2;

	GtkTextIter iter1, iter2;

	gtk_text_buffer_get_iter_at_line_offset(buffer3, &iter1, line1, start);
	gtk_text_buffer_get_iter_at_line_offset(buffer3, &iter2, line2, end);
	gtk_text_buffer_select_range(buffer3, &iter1, &iter2);

	GDK_THREADS_LEAVE();
}

/*
* 选中数据包封装信息中的某一层时，十六进制区域相应高亮选中
*/
void on_treeview_single_selection_changed(GtkTreeSelection * select,
					  gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;

	if (gtk_tree_selection_get_selected(select, &model, &iter)) {

		gchar *name;
		gtk_tree_model_get(model, &iter, 0, &name, -1);

		int start, end;
		if (strstr(name, "Ethernet")) {
			start = 0;
			end = 14;
		} else if (strstr(name, "ARP")) {
			start = 14;
			end = 42;
		} else if (strstr(name, "IPv6")) {
			start = 14;
			end = 38;
		} else if (strstr(name, "IPv4")) {
			start = 14;
			end = 34;
		} else if (strstr(name, "ICMP")) {
			start = 34;
			end = 42;
		} else if (strstr(name, "TCP")) {
			start = 34;
			end = 54;
		} else if (strstr(name, "UDP")) {
			start = 34;
			end = 42;
		} else if (strstr(name, "Data")) {
			start = 42;
			end = pktlen;
		} else {
			start = 0;
			end = 0;
		}

		//pthread_t tid1,tid2;
		srange.start = start;
		srange.end = end;
		//pthread_create(&tid1, NULL, (void *)show_selection_hex, &srange);
		//pthread_create(&tid2, NULL, (void *)show_selection_ascii, &srange);

		g_thread_new("show_hex", (GThreadFunc) show_selection_hex,
			     &srange);
		//g_thread_new("show_ascii", show_selection_ascii, &srange);
		//show_selection_ascii(&srange);
		//show_selection_hex(start ,end);
		//show_selection_ascii(start, end);
		g_free(name);

	}
}
