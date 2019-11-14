#include <dirent.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gtk/gtk.h>

#define APPLICATION_NAME "Pollux"
#define APPLICATION_BUILD "2.0.4"
#define MAIN_WINDOW_DEFAULT_WIDTH 1000
#define MAIN_WINDOW_DEFAULT_HEIGHT 350
#define APPLICATION_ICON_LARGE_PATH "/home/oppa/pollux_logo.svg"
#define APPLICATION_ICON_SMALL_PATH "/home/oppa/pollux_logo_small.svg"

typedef void (gcallback_t *)(GtkWidget *, gpointer);

static void setup_window(GtkApplication *, gpointer) __nonnull ((1,2));
static void start_scan(GtkWidget *, gpointer) __nonnull ((1,2));
static void on_digest_select(GtkWidget *, gpointer) __nonnull((1,2));

enum
{
	DIGEST_MD5 = 0,
	DIGEST_SHA256,
	DIGEST_SHA512,
	NR_DIGESTS
};

struct digest_opt
{
	GtkWidget *radio;
	gint type;
	gchar *name;
	gcallback_t set_digest_func;
};

GtkWidget *radio_md5;
GtkWidget *radio_sha256;
GtkWidget *radio_sha512;

static void on_digest_select(GtkWidget *, gpointer);

#define DIGEST_RADIO 0
#define DIGEST_TYPE 1
#define DIGEST_NAME 2
#define DIGEST_FUNC 3

struct digest_opt hash_digests[NR_DIGESTS] =
{
	{ radio_md5, DIGEST_MD5, "MD5", on_digest_select },
	{ radio_sha256, DIGEST_SHA256, "SHA256", on_digest_select },
	{ radio_sha512, DIGEST_SHA512, "SHA512", on_digest_select }
};

static void
set_application_icon(GtkWidget *window)
{
	GdkPixbuf *pixbuf;
	GError *error = NULL;

	pixbuf = gdk_pixbuf_new_from_file(APPLICATION_ICON_LARGE_PATH, &error);

	if (error)
	{
		fprintf(stderr, "*** Failed to set application icon (%s) ***\n", error->message);
		g_error_free(error);
		return;
	}

	gtk_window_set_icon(GTK_WINDOW(window), pixbuf);
	g_object_unref(pixbuf);

	return;
}

struct file_node
{
	gchar *path;
	gsize size;
	gchar *digest;
	struct file_node *left;
	struct file_node *right;
	struct file_node *bucket; /* files with same size but different hash */
};

struct pollux_ctx
{
	guint nr_duplicates;
	guint nr_files;
	guint wasted_mem;
	struct file_node *root;

	struct options
	{
		gint digest_type;
		gint no_hidden;
	} options;

/*
 * Do not keep an ITER arg here because tree
 * iters are ephemeral, living on the stack.
 */
	GtkTreeModel *tree_duplicates_model;
	GtkWidget *tree_duplicates_view;
};

static struct options o;

enum
{
	COL_FILENAME,
	COL_FILESIZE,
	NR_COL_FILE
};

struct pollux_ctx plx_ctx = {0};

static void
on_digest_select(GtkWidget *widget, gpointer type)
{
	plx_ctx.options.digest_type = *(gint *)type;
	g_printf("Using digest #%d\n", plx_ctx.options.digest_type);
	return;
}

static void
on_show_folders(GtkWidget *widget, gpointer data)
{
	GtkWidget *new_window;
	GtkWidget *tree_view;
	GtkListStore *list_store;
	GtkTreeIter iter;
	GtkCellRenderer *renderer;
	DIR *dirp;
	struct dirent *dinf;
	struct stat statb;
#ifndef PATHMAX
# define PATHMAX 1024
#endif
	gchar tmp[PATHMAX];
	gchar *p;

	gchar *home = getenv("HOME");
	strcpy(tmp, home);

	dirp = opendir(home);
	if (!dirp)
	{
		g_print("*** Failed to open %s ***\n", home);
		return;
	}

	list_store = gtk_list_store_new(NR_COL_FILE, G_TYPE_STRING, G_TYPE_UINT);

	lstat(home, &statb);

	gtk_list_store_append(list_store, &iter);
	gtk_list_store_set(list_store, &iter, COL_FILENAME, home, COL_FILESIZE, (guint)statb.st_size, -1);

	p = (tmp + strlen(tmp));
	*p++ = '/';

	while ((dinf = readdir(dirp)))
	{
		if (!strcmp(".", dinf->d_name) ||
			!strcmp("..", dinf->d_name) ||
			dinf->d_name[0] == '.')
		{
			continue;
		}

		strcpy(p, dinf->d_name);
		lstat(tmp, &statb);

		if (!S_ISDIR(statb.st_mode))
			continue;

		gtk_list_store_append(list_store, &iter);
		gtk_list_store_set(list_store, &iter, COL_FILENAME, tmp, COL_FILESIZE, (guint)statb.st_size, -1);
	}

	closedir(dirp);

	tree_view = gtk_tree_view_new();
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tree_view), -1, "Filename", renderer, "text", COL_FILENAME, NULL);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tree_view), -1, "File Size", renderer, "text", COL_FILESIZE, NULL);

	gtk_tree_view_set_model(GTK_TREE_VIEW(tree_view), GTK_TREE_MODEL(list_store));
	g_object_unref(list_store);

	new_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(new_window), home);
	gtk_window_set_default_size(GTK_WINDOW(new_window), 550, 350);

	GtkWidget *grid = gtk_grid_new();

	gtk_container_add(GTK_CONTAINER(new_window), grid);
	gtk_grid_attach(GTK_GRID(grid), tree_view, 0, 0, 1, 1);

	gtk_widget_show_all(new_window);

	return;
}

static void
setup_window(GtkApplication *app, gpointer data)
{
	// the window will be cast using the macro GTK_WINDOW()
	GtkWidget		*window = NULL;
	//the grid will be cast using the macro GTK_GRID()
	GtkWidget		*grid_left = NULL;
	//GtkListStore *list_store;
	//GtkWidget *tree_view;
	//GtkTreeIter iter;
	//GtkCellRenderer *renderer;
	GtkWidget *digest_opts_label;
	GtkWidget *radio_digest_box;
	GtkWidget *runtime_opts_label;
	GtkWidget *check_opt_nodelete;
	GtkWidget *check_opt_nohidden;
	GtkWidget *box2;
	GtkWidget *btn_scan;
	GtkWidget *btn_show_folders;
	GtkWidget *btn_quit;
	gint i;
	
	// set up the window
	window = gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window), APPLICATION_NAME" v"APPLICATION_BUILD);
	// 2nd arg is x-axis, 3rd is y-axis
	gtk_window_set_default_size(GTK_WINDOW(window), MAIN_WINDOW_DEFAULT_WIDTH, MAIN_WINDOW_DEFAULT_HEIGHT);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_container_set_border_width(GTK_CONTAINER(window), 50);

	// get a grid container and add it to the window
	grid_left = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(window), grid_left);

	btn_quit = gtk_button_new_with_label("Quit");
/*
 * If you use just g_signal_connect() to do this, then the actual button widget
 * would be destroyed, not the window!
 */
	g_signal_connect_swapped(btn_quit, "clicked", G_CALLBACK(gtk_widget_destroy), window);

	set_application_icon(window);

	digest_opts_label = gtk_label_new("Digest:");

	radio_digest_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, NR_DIGESTS);
	gtk_box_set_homogeneous(GTK_BOX(radio_digest_box), TRUE);

	digests[0].radio = gtk_radio_button_new_with_label(NULL, digests[0].name);
	g_signal_connect(digests[0].radio, "clicked", G_CALLBACK(digests[0].set_digest_func), (gpointer)&digests[0].type);
	gtk_box_pack_start(GTK_BOX(radio_digest_box), digests[0].radio, FALSE, FALSE, 0);

/*
 * Create radio buttons for user to select the hash digest algorithm
 * they wish to use in order to compare files with one another.
 */
	for (i = 1; i < NR_DIGESTS; ++i)
	{
		digests[i].radio = gtk_radio_button_new_with_label_from_widget(digests[0].radio, digests[i].name);
		g_signal_connect(digests[i].radio, "clicked", G_CALLBACK(digests[i].set_digest_func), (gpointer)&digests[i].type);
		gtk_box_pack_start(GTK_BOX(radio_digest_box), digests[i].radio, FALSE, FALSE, 0);
	}

	btn_scan = gtk_button_new_with_label("Start Scanning");
	btn_show_folders = gtk_button_new_with_label("Show Files");

	g_signal_connect(btn_show_folders, "clicked", G_CALLBACK(on_show_folders), NULL);

	// gtk_grid_attach(GtkGrid *, GtkWidget *, gint left, gint top, gint width, gint height)
	gtk_grid_attach(GTK_GRID(grid_left), digest_opts_label, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid_left), radio_digest_box, 1, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(grid_left), btn_quit, 0, 2, 1, 1);
	gtk_grid_attach(GTK_GRID(grid_left), btn_scan, 0, 3, 1, 1);
	gtk_grid_attach(GTK_GRID(grid_left), btn_show_folders, 0, 4, 1, 1);

	GtkWidget *info = gtk_label_new(
		"\tPollux v" APPLICATION_BUILD"\n"
		"\n"
		"\tWritten by Gary Hannah");

	gtk_grid_attach(GTK_GRID(grid_left), info, 3, 1, 1, 1);

	gtk_widget_show_all(window);
}

struct node
{
	size_t size;
	gchar *path;
	struct node *left;
	struct node *right;
	struct node *array; /* For storing those with same file sizes but different hashes */
};

static void
start_scan(GtkWidget *widget, gpointer data)
{
	// TODO
}

int
main(int argc, char *argv[])
{
	GtkApplication		*app = NULL;
	int			status;
	/* a GtkWindow can hold only one widget at a time; so use a vbox to contain
	 * several widgets and then insert the box into the window
	 */
	// gtk_vbox_new() is deprecated; gtk_box_new() should also be avoided; should switch to
	// using a GtkGrid instead (aux dires des développeurs de GTK);
	//GtkWidget		*vbox = NULL;

	/*GtkBuilder		*builder = NULL;
	GObject			*window = NULL;
	GObject			*button = NULL;
	GError			*error = NULL;*/

	/* this will parse any commandline arguments related to the GUI
	 * and will remove them from argv, and will leave the remaining
	 * for the actual application to parse.
	 */
	//gtk_init(&argc, &argv);

	app = gtk_application_new("org.pollux", G_APPLICATION_FLAGS_NONE);
	g_signal_connect(app, "activate", G_CALLBACK(setup_window), NULL);
	// do not make the mistake of using the GTK_APPLICATION() macro
	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(app);

	exit(status);
}
