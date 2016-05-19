#ifndef SNIFFER_H
#define SNIFFER_H

#include<stdlib.h>
#include<gtk/gtk.h>
#include<pthread.h>

GtkBuilder *builder;
void edit_packet_list_view(GtkWidget * view);
/*signal function*/
void on_imagemenuitem_interface_activate();
void on_button_if_cancel_clicked(GtkWidget * gw, GtkTreeView * view);
void on_treeview_overall_selection_changed(GtkTreeSelection * select,
					   gpointer data);
void on_treeview_single_selection_changed(GtkTreeSelection * select,
					  gpointer data);
#endif
