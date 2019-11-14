#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

#define DIGEST_ASCII_MAX_SIZE (EVP_MAX_MD_SIZE * 2)

#ifndef PATHMAX
# define PATHMAX 1024
#endif

#define clear_struct(s) memset((s), 0, sizeof((*s)))

#define PLX_ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

typedef void (*gcallback_t)(GtkWidget *, gpointer);

static void setup_window(GtkApplication *, gpointer) __nonnull ((1,2));
static void on_digest_select(GtkWidget *, gpointer) __nonnull((1,2));
static void on_start_scan(GtkWidget *, gpointer) __nonnull((1));

static gchar home_dir[PATH_MAX];
static gchar *path_buf;

struct digest_size
{
	gsize binary;
	gsize ascii;
};

enum
{
	DIGEST_MD5 = 0,
	DIGEST_SHA256,
	DIGEST_SHA512,
	NR_DIGESTS
};

enum
{
	COL_FILE_DIGEST,
	NR_COLS_DUPS
};

#define plx_get_digest_size_binary(type) (digest_sizes[(type)].binary)
#define plx_get_digest_size_ascii(type) (digest_sizes[(type)].ascii)

struct digest_size digest_sizes[NR_DIGESTS] =
{
	{ 16, 32 },
	{ 32, 64 },
	{ 64, 128 }
};

struct digest_opt
{
	GtkWidget *radio;
	gint type;
	gchar *name;
	gcallback_t set_digest_func;
};

static GtkWidget radio_md5;
static GtkWidget radio_sha256;
static GtkWidget radio_sha512;

struct digest_opt hash_digests[NR_DIGESTS] =
{
	{ &radio_md5, DIGEST_MD5, "MD5", on_digest_select },
	{ &radio_sha256, DIGEST_SHA256, "SHA256", on_digest_select },
	{ &radio_sha512, DIGEST_SHA512, "SHA512", on_digest_select }
};

struct file_node
{
	gchar *path;
	gsize size;
	gchar *digest;
	struct file_node *left;
	struct file_node *right;
	struct file_node *bucket; /* files with same size but different hash */
	gint nr_bucket;
};

#define PLX_INC_FILES(p) ++((p)->nr_files)
#define PLX_INC_DUPS(p) ++((p)->nr_duplicates)
#define PLX_ADD_MEM(p, m) ((p)->wasted_mem += (m))

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

#define digest_type options.digest_type
#define no_hidden options.no_hidden

/*
 * Do not keep an ITER arg here because tree
 * iters are ephemeral, living on the stack.
 */
	struct tree
	{
		GtkTreeStore *store;
		GtkWidget *view;
		gint initialised;
	} tree;
};

struct pollux_ctx plx_ctx = {0};
struct file_node *root;

static void
plx_dup_digest(gchar **target, gchar *digest, gsize size)
{
	(*target) = calloc(PLX_ALIGN_SIZE(size), 1);
	memcpy((*target), digest, size);
	(*target)[size] = 0;

	return;
}

const char const hexchars[16] = "0123456789abcdef";

static void
plx_get_digest_ascii(gchar *ascii, gchar *binary, gsize size)
{
	gint i;
	gint k;

	for (i = 0, k = 0; (gsize)i < size; ++i)
	{
		ascii[k++] = hexchars[((binary[i] >> 4) & 0xf)];
		ascii[k++] = hexchars[(binary[i] & 0xf)];
	}

	ascii[k] = 0;
	return;
}

static void
plx_dup_add_pair(struct pollux_ctx *ctx, gchar *first, gchar *second, gchar *digest)
{
	g_return_if_fail(ctx != NULL);
	g_return_if_fail(first != NULL);
	g_return_if_fail(second != NULL);

	if (!ctx->tree.initialised)
	{
		ctx->tree.store = gtk_tree_store_new(NR_COLS_DUPS, G_TYPE_STRING);
		ctx->tree.initialised = 1;
	}

	GtkTreeStore *store = GTK_TREE_STORE(ctx->tree.store);
	GtkTreeIter iter;
	GtkTreeIter child;
	gsize binary_size = plx_get_digest_size_binary(ctx->digest_type);
	static gchar digest_ascii[DIGEST_ASCII_MAX_SIZE];

	plx_get_digest_ascii(digest_ascii, digest, binary_size);

	gtk_tree_store_append(store, &iter, NULL);
	gtk_tree_store_set(store, &iter, COL_FILE_DIGEST, digest_ascii, -1);
	gtk_tree_store_append(store, &child, &iter);
	gtk_tree_store_set(store, &child, 0, first, -1);
	gtk_tree_store_append(store, &child, &iter);
	gtk_tree_store_set(store, &child, 0, second, -1);

	return;
}

#define READ_BLOCK 4096

static gint
plx_get_file_digest(gchar **digest, gchar *filename)
{
	guint len = 0;
	EVP_MD_CTX *ctx = NULL;
	gint fd = -1;
	struct stat statb;
	gsize toread = 0;
	gssize bytes = 0;
	gchar block[READ_BLOCK+16];

	clear_struct(&statb);

	if (lstat(filename, &statb) < 0)
		goto fail;

	if ((fd = open(filename, O_RDONLY)) < 0)
		goto fail;

	if (!(ctx = EVP_MD_CTX_create()))
		goto fail;

	switch(plx_ctx.digest_type)
	{
		case DIGEST_MD5:
			if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
				goto fail;
			break;
		case DIGEST_SHA512:
			if (1 != EVP_DigestInit_ex(ctx, EVP_sha512(), NULL))
				goto fail;
			break;
		default:
			if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
				goto fail;
			break;
	}

	toread = statb.st_size;

	while (toread > 0 && (bytes = read(fd, block, READ_BLOCK)))
	{
		if (bytes < 0)
		{
			g_print("*** Failed to read from file %s ***\n", filename);
			goto fail;
		}

		block[bytes] = 0;

		if (1 != EVP_DigestUpdate(ctx, block, bytes))
			goto fail;

		toread -= bytes;
	}

	*digest = calloc(PLX_ALIGN_SIZE(plx_get_digest_size_binary(plx_ctx.digest_type)+1), 1);
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &len))
		goto fail;

	close(fd);
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;

	return 0;

	fail:

	close(fd);
	fd = -1;

	if (ctx != NULL)
	{
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	return -1;
}

static gchar *
plx_digest_name_str(gint type)
{
	switch(type)
	{
		case DIGEST_SHA256:
			return "SHA256";
			break;
		case DIGEST_SHA512:
			return "SHA512";
			break;
		default:
			return "MD5";
			break;
	}

	return NULL;
}

static void
plx_print_digest(gchar *digest)
{
	gchar ascii[DIGEST_ASCII_MAX_SIZE];

	plx_get_digest_ascii(ascii, digest, plx_get_digest_size_binary(plx_ctx.digest_type));
	g_print("%s\n", ascii);

	return;
}

static gint
__insert_file_node(gchar *path, gsize size)
{
	if (!root)
	{
		root = malloc(sizeof(struct file_node));

		assert(root);

		root->left = NULL;
		root->right = NULL;
		root->bucket = NULL;
		root->digest = NULL;

		root->path = strdup(path);
		assert(root->path);
		root->size = size;

		return 0;
	}

	struct file_node *nptr = root;
	gchar *current_digest = NULL;

	while (1)
	{
		if (size < nptr->size)
		{
			if (!nptr->left)
			{
				nptr->left = malloc(sizeof(struct file_node));
				assert(nptr->left);

				nptr->left->left = NULL;
				nptr->left->right = NULL;
				nptr->left->bucket = NULL;
				nptr->left->digest = NULL;

				nptr->left->path = strdup(path);
				assert(nptr->left->path);
				nptr->left->size = size;

				break;
			}
			else
			{
				nptr = nptr->left;
				continue;
			}
		}
		else
		if (size > nptr->size)
		{
			if (!nptr->right)
			{
				nptr->right = malloc(sizeof(struct file_node));
				assert(nptr->right);

				nptr->right->left = NULL;
				nptr->right->right = NULL;
				nptr->right->bucket = NULL;
				nptr->right->digest = NULL;

				nptr->right->path = strdup(path);
				assert(nptr->right->path);
				nptr->right->size = size;

				break;
			}
			else
			{
				nptr = nptr->right;
				continue;
			}
		}
		else
		{
/*
 * Only calculate hash digests when we have a
 * collision of sizes.
 */
			gsize digest_size = plx_get_digest_size_binary(plx_ctx.digest_type);

			if (!nptr->digest)
				plx_get_file_digest(&nptr->digest, nptr->path);

			plx_get_file_digest(&current_digest, path);

			if (!memcmp(current_digest, nptr->digest, digest_size))
			{
				PLX_INC_DUPS(&plx_ctx);
				PLX_ADD_MEM(&plx_ctx, size);
				plx_dup_add_pair(&plx_ctx, nptr->path, path, nptr->digest);
				free(current_digest);
				break;
			}
			else
			{
/*
 * Files that have the same size but different hash digests
 * are saved in the BUCKET member of the node with that size.
 */
				if (!nptr->bucket)
				{
					nptr->nr_bucket = 1;
					nptr->bucket = calloc(nptr->nr_bucket, PLX_ALIGN_SIZE(digest_size + 1));

					nptr->bucket[nptr->nr_bucket - 1].digest = calloc(PLX_ALIGN_SIZE(digest_size + 1), 1);
					memcpy(nptr->bucket[nptr->nr_bucket - 1].digest, current_digest, digest_size);
					nptr->bucket[nptr->nr_bucket - 1].digest[digest_size] = 0;
					nptr->bucket[nptr->nr_bucket - 1].path = strdup(path);
					nptr->bucket[nptr->nr_bucket - 1].size = size;
				}
				else
				{
					gint bi;
					gint nr_dups = plx_ctx.nr_duplicates;

					for (bi = 0; bi < (nptr->nr_bucket - 1); bi += 2)
					{
						if (!memcmp(current_digest, nptr->bucket[bi].digest, digest_size))
						{
							PLX_INC_DUPS(&plx_ctx);
							PLX_ADD_MEM(&plx_ctx, size);
							plx_dup_add_pair(&plx_ctx, nptr->bucket[bi].path, path, nptr->bucket[bi].digest);
						}
						else
						if (!memcmp(current_digest, nptr->bucket[bi+1].digest, digest_size))
						{
							PLX_INC_DUPS(&plx_ctx);
							PLX_ADD_MEM(&plx_ctx, size);
							plx_dup_add_pair(&plx_ctx, nptr->bucket[bi+1].path, path, nptr->bucket[bi+1].digest);
						}
					}

					if (nptr->nr_bucket & 1)
					{
						if (!memcmp(current_digest, nptr->bucket[bi].digest, digest_size))
						{
							PLX_INC_DUPS(&plx_ctx);
							PLX_ADD_MEM(&plx_ctx, size);
							plx_dup_add_pair(&plx_ctx, nptr->bucket[bi].path, path, nptr->bucket[bi].digest);
						}
					}

					if (nr_dups == plx_ctx.nr_duplicates)
					{
						++nptr->nr_bucket;
						nptr->bucket = realloc(nptr->bucket, PLX_ALIGN_SIZE((nptr->nr_bucket * sizeof(struct file_node))));

						nptr->bucket[nptr->nr_bucket - 1].digest = calloc(PLX_ALIGN_SIZE(digest_size+1), 1);
						memcpy(nptr->bucket[nptr->nr_bucket - 1].digest, current_digest, digest_size);
						nptr->bucket[nptr->nr_bucket - 1].digest[digest_size] = 0;
						nptr->bucket[nptr->nr_bucket - 1].path = strdup(path);
						nptr->bucket[nptr->nr_bucket - 1].size = size;
					}
				} /* else nptr->bucket */
			} /* else memcmp(...) */

			if (current_digest)
				free(current_digest);

			break;

		} /* else size == nptr->size */
	} /* while (1) */

	return 0;
}

static void
plx_destroy_tree(struct file_node *node)
{
	if (node->left)
		plx_destroy_tree(node->left);

	if (node->right)
		plx_destroy_tree(node->right);

	free(node->path);
	if (node->bucket)
		free(node->bucket);
	if (node->digest)
		free(node->digest);

	free(node);
	return;
}

static gint
__do_scan(gchar *path)
{
	gsize len = strlen(path);
	gchar *p;
	struct dirent *dinf;
	DIR *dirp;
	struct stat statb;

	p = (path + len);

	if (*(p-1) != '/')
	{
		*p++ = '/';
		*p = 0;

		++len;
	}

	dirp = opendir(path);
	if (!dirp)
		return -1;

	clear_struct(&statb);

	while ((dinf = readdir(dirp)))
	{
		if (!strcmp("..", dinf->d_name) ||
			!strcmp(".", dinf->d_name) ||
			dinf->d_name[0] == '.')
		{
			continue;
		}

		strcpy(p, dinf->d_name);
		lstat(path, &statb);

		if (S_ISREG(statb.st_mode) && access(path, R_OK) == 0)
		{
			PLX_INC_FILES(&plx_ctx);
			__insert_file_node(path, statb.st_size);
		}
		else
		if (S_ISDIR(statb.st_mode))
		{
			if (__do_scan(path) == -1)
				goto fail;
		}
		else
		{
			continue;
		}
	}

	closedir(dirp);
	dirp = NULL;

	*p = 0;
	return 0;

	fail:
	if (dirp)
		closedir(dirp);
	*p = 0;
	return -1;
}

static void
plx_show_duplicate_files(struct pollux_ctx *ctx)
{
	GtkWidget *window;
	GtkWidget *view = ctx->tree.view;
	GtkWidget *stats_box;
	GtkTreeStore *store;
	GtkCellRenderer *renderer;
	gchar col_name[64];

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(window), "Duplicate Files");
	gtk_window_set_default_size(GTK_WINDOW(window), 1500, 350);

	view = gtk_tree_view_new();
	renderer = gtk_cell_renderer_text_new();

	sprintf(col_name, "%d duplicates [%s digest]", plx_ctx.nr_duplicates, plx_digest_name_str(plx_ctx.digest_type));
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1, col_name, renderer, "text", 0, NULL);

	store = ctx->tree.store;
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), GTK_TREE_MODEL(store));
	g_object_unref(store);

	stats_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_box_set_homogeneous(GTK_BOX(stats_box), TRUE);

	gchar tmp[32];
	GtkWidget *label_nr_files = gtk_label_new("Files scanned: ");
	gtk_box_pack_start(GTK_BOX(stats_box), label_nr_files, FALSE, FALSE, 0);
	sprintf(tmp, "%d", plx_ctx.nr_files);
	GtkWidget *stats_nr_files = gtk_label_new(tmp);
	gtk_box_pack_start(GTK_BOX(stats_box), stats_nr_files, FALSE, FALSE, 0);
	GtkWidget *label_nr_dups = gtk_label_new("Duplicates: ");
	gtk_box_pack_start(GTK_BOX(stats_box), label_nr_dups, FALSE, FALSE, 0);
	sprintf(tmp, "%d", plx_ctx.nr_duplicates);
	GtkWidget *stats_nr_duplicates = gtk_label_new(tmp);
	gtk_box_pack_start(GTK_BOX(stats_box), stats_nr_duplicates, FALSE, FALSE, 0);
	GtkWidget *label_wasted_mem = gtk_label_new("Wasted Mem: ");
	gtk_box_pack_start(GTK_BOX(stats_box), label_wasted_mem, FALSE, FALSE, 0);
	sprintf(tmp, "%d", plx_ctx.wasted_mem);
	GtkWidget *stats_wasted_mem = gtk_label_new(tmp);
	gtk_box_pack_start(GTK_BOX(stats_box), stats_wasted_mem, FALSE, FALSE, 0);

	GtkWidget *grid = gtk_grid_new();

	gtk_grid_attach(GTK_GRID(grid), stats_box, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), view, 0, 1, 1, 1);
	gtk_container_add(GTK_CONTAINER(window), grid);

	gtk_widget_show_all(window);

	return;
}

void
on_start_scan(GtkWidget *widget, gpointer data)
{
	gchar *home = getenv("HOME");

	if (!home)
	{
		g_print("*** Failed to get home directory! ***\n");
		goto fail;
	}

	strcpy(home_dir, home);

	path_buf = calloc(PLX_ALIGN_SIZE(PATHMAX*2), 1);
	strcpy(path_buf, home_dir);
	strcat(path_buf, "/Documents");

	if (__do_scan(path_buf) == -1)
		goto fail;

	plx_show_duplicate_files(&plx_ctx);

	plx_destroy_tree(root);
	free(path_buf);

	return;

	fail:
	return;
}

enum
{
	COL_FILENAME,
	COL_FILESIZE,
	COL_NR_FILE
};


static void
on_digest_select(GtkWidget *widget, gpointer type)
{
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
	{
		plx_ctx.digest_type = *(gint *)type;
		g_print("Using digest #%d\n", plx_ctx.digest_type);
	}

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

	list_store = gtk_list_store_new(COL_NR_FILE, G_TYPE_STRING, G_TYPE_UINT);

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

/*
 * Create radio buttons for user to select the hash digest algorithm
 * they wish to use in order to compare files with one another.
 */
	digest_opts_label = gtk_label_new("Digest:");

	radio_digest_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, NR_DIGESTS);
	gtk_box_set_homogeneous(GTK_BOX(radio_digest_box), TRUE);

	hash_digests[0].radio = gtk_radio_button_new_with_label(NULL, hash_digests[0].name);
	g_signal_connect(hash_digests[0].radio, "toggled", G_CALLBACK(hash_digests[0].set_digest_func), (gpointer)&hash_digests[0].type);
	gtk_box_pack_start(GTK_BOX(radio_digest_box), hash_digests[0].radio, FALSE, FALSE, 0);

	for (i = 1; i < NR_DIGESTS; ++i)
	{
		hash_digests[i].radio = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(hash_digests[0].radio), hash_digests[i].name);
		g_signal_connect(hash_digests[i].radio, "clicked", G_CALLBACK(hash_digests[i].set_digest_func), (gpointer)&hash_digests[i].type);
		gtk_box_pack_start(GTK_BOX(radio_digest_box), hash_digests[i].radio, FALSE, FALSE, 0);
	}

	btn_scan = gtk_button_new_with_label("Start Scan");
	btn_show_folders = gtk_button_new_with_label("Show Folders");

	g_signal_connect(btn_scan, "clicked", G_CALLBACK(on_start_scan), NULL);
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

	plx_ctx.digest_type = DIGEST_MD5;
	app = gtk_application_new("org.pollux", G_APPLICATION_FLAGS_NONE);
	g_signal_connect(app, "activate", G_CALLBACK(setup_window), NULL);
	// do not make the mistake of using the GTK_APPLICATION() macro
	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(app);

	exit(status);
}
