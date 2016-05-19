#include"sniffer.h"

/* start here*/
int main(int argc, char *argv[])
{
	GtkWidget *window;
	GtkWidget *overall_view, *single_view;
	GtkTreeSelection *selection_overall, *selection_single;

	if (getuid()) {
		printf("[+] The program need root permission.\n\n");
		exit(1);
	}
	gdk_threads_init();

	gtk_init(&argc, &argv);

	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "sniffer.glade", NULL);

	window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));
	single_view =
	    GTK_WIDGET(gtk_builder_get_object(builder, "treeview_single"));
	overall_view =
	    GTK_WIDGET(gtk_builder_get_object(builder, "treeview_overall"));
	edit_packet_list_view(overall_view);

	selection_overall =
	    gtk_tree_view_get_selection(GTK_TREE_VIEW(overall_view));
	selection_single =
	    gtk_tree_view_get_selection(GTK_TREE_VIEW(single_view));

	g_signal_connect(selection_overall, "changed",
			 G_CALLBACK(on_treeview_overall_selection_changed),
			 NULL);
	g_signal_connect(selection_single, "changed",
			 G_CALLBACK(on_treeview_single_selection_changed),
			 NULL);

	gtk_builder_connect_signals(builder, NULL);

	gtk_widget_show_all(window);

	gtk_main();
	return 0;
}
