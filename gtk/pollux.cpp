#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <list>
#include <map>
#include <gtk/gtk.h>

#define PROG_NAME "Pollux"
#define PROG_NAME_DBUS "org.weemonkey.pollux"
#define POLLUX_BUILD "0.0.1"
#define POLLUX_LOGO "./pollux_logo2.svg"
#define PROG_COMMENTS "Pollux -- Find duplicate files based on hash digests"
#define PROG_AUTHORS { "Gary Hannah", (gchar *)NULL }
#define PROG_WEBSITE "https://127.0.0.1:80/?real=false&amp;fake=true"

#define WIN_DEFAULT_WIDTH 1000
#define WIN_DEFAULT_HEIGHT 350

#define DIGEST() EVP_sha512()
#define DIGEST_SIZE (EVP_MD_size(DIGEST()) * 2)

static gchar *get_file_digest(gchar *) __nonnull((1)) __wur;

static struct sigaction sigint_old;
static struct sigaction sigint_new;
static sigjmp_buf __root_env__;

typedef void (*gcallback_t)(GtkWidget *, gpointer);

void on_digest_select(GtkWidget *, gpointer);
void create_window(void);
void create_menu_bar(void);

enum
{
	DIGEST_MD5,
	DIGEST_SHA256,
	DIGEST_SHA512,
	NR_DIGESTS
};

#define __DEFAULT_DIGEST DIGEST_MD5

static GtkApplication *app;
static GtkWidget *window;
static GtkWidget *grid;
static GtkWidget *menu_bar;
static GtkWidget *file_menu;
static GtkWidget *item_file;
static GtkWidget *item_file_quit;
static GtkWidget *options_menu;
static GtkWidget *digests_menu;
static GtkWidget *item_options;
static GtkWidget *item_digests;
static GtkWidget item_digest_md5;
static GtkWidget item_digest_sha256;
static GtkWidget item_digest_sha512;

static GtkWidget *button_start_scan;
static GtkWidget *status_bar;
static GtkWidget *image;
static GdkPixbuf *icon_pixbuf;

//static GtkWidget *about;

static GList *list_digests;

struct Digest
{
	GtkWidget *item;
	gint type;
	const gchar *name;
	gcallback_t func;
};

static struct Digest menu_digests[NR_DIGESTS] =
{
	{ &item_digest_md5, DIGEST_MD5, (const gchar *)"MD5", on_digest_select },
	{ &item_digest_sha256, DIGEST_SHA256, (const gchar *)"SHA256", on_digest_select },
	{ &item_digest_sha512, DIGEST_SHA512, (const gchar *)"SHA512", on_digest_select }
};

/*
 * ___________________________________________________________________________
 * | File    Options                                                          |
 * |__________________________________________________________________________|
 * |                                                                          |
 * |                                   Duplicates: \"nr_dups\"                |
 * |                                                                          |
 * |                                                                          |
 * |     [start scan]                                                         |
 * |                                                                          |
 * |                                                                          |
 * |                                                                          |
 * |                                                                          |
 * | testing \"/path/to/file.file_extension\"                                 |
 * |__________________________________________________________________________|
 *
 * Ideally, want to have a button for choosing starting directory for scan.
 * Need to figure out how to create a window that shows the file system as
 * a tree (perhaps there is a well-known built-in function that comes with
 * GTK/GNOME that does all of that under the hood.
 *
 */

class fNode
{
	public:

	gchar *digest;
	gchar *name;
	gsize size;
	fNode *left;
	fNode *right;
	fNode *parent;

	fNode();
	~fNode();

	bool has_digest(void)
	{
		return this->have_digest;
	}

	void got_digest(bool tvalue)
	{
		this->have_digest = tvalue;
	}

	bool been_added(void)
	{
		return this->added;
	}

	void set_added(bool tvalue)
	{
		this->added = tvalue;
	}

	void add_to_bucket(fNode& node)
	{
		this->bucket.push_back(node);
		this->nr_bucket += 1;
	}

	bool bucket_contains(gchar *digest, gsize size)
	{
		for (std::list<fNode>::iterator it = this->bucket.begin(); it != this->bucket.end(); ++it)
		{
			if (!memcmp(digest, it->digest, size))
			{
				return true;
			}
		}

		return false;
	}

	gint nr_items_bucket(void)
	{
		return this->nr_bucket;
	}

	private:

	bool have_digest;
	bool added;
	std::list<fNode> bucket;
	gsize nr_bucket;
};

fNode::fNode(void)
{
	this->digest = NULL;
	this->name = NULL;
	this->size = 0;
	this->left = NULL;
	this->right = NULL;
	this->parent = NULL;
	this->have_digest = false;
	this->added = false;
	this->nr_bucket = 0;
}

fNode::~fNode(void)
{
	if (this->digest)
		free(this->digest);

	if (this->name)
		free(this->name);
}

/*
 * Duplicate file node.
 */
class dNode
{
	public:

	gchar *name;

	dNode();
};

dNode::dNode(void)
{
	this->name = NULL;
}

/*
 * Now using a map of type std::map<gchar *,std::list<dNode> >
 *
 * Gives O(log(N)) search time to find the linked list of
 * files that match the digest (which is the key).
 */
#if 0
/*
 * Linked list of digests, containing
 * a head pointer to linked list of
 * all the files that have this digest.
 */
class dList
{
	public:

	gsize nr_nodes;
	std::list<dNode> files;

	dList();

	gint get_nr_items(void)
	{
		return this->nr_nodes;
	}

	gint add_node(dNode node)
	{
		this->files.push_back(node);
		this->nr_nodes += 1;
	}
};

dList::dList(void)
{
	this->digest = NULL;
	this->nr_nodes = 0;
}
#endif

class fTree
{
	public:

	gsize nr_nodes;

	fTree();
	~fTree();

	void insert_file(gchar *name)
	{
		struct stat statb;
		gsize size;

		lstat(name, &statb);
		size = statb.st_size;

		if (!this->root)
		{
			this->root = new fNode();
			this->root->name = strdup(name);
			this->root->size = size;
			this->root->left = NULL;
			this->root->right = NULL;
			this->root->parent = NULL;
			this->nr_nodes += 1;

			return;
		}

		fNode *n = this->root;

		while (true)
		{
			if (size < n->size)
			{
				if (!n->left)
				{
					n->left = new fNode();
					n->left->name = strdup(name);
					n->left->size = size;
					n->left->parent = n;
					this->nr_nodes += 1;
#ifdef DEBUG
					std::cerr << "Inserted @ " << &n->left << std::endl;
#endif
					return;
				}
				else
				{
					n = n->left;
					continue;
				}
			}
			else
			if (size > n->size)
			{
				if (!n->right)
				{
					n->right = new fNode();
					n->right->name = strdup(name);
					n->right->size = size;
					n->right->parent = n;
					this->nr_nodes += 1;
#ifdef DEBUG
					std::cerr << "Inserted @ %p " << &n->right << std::endl;
#endif
					return;
				}
				else
				{
					n = n->right;
					continue;
				}
			}
			else /* size == n->size */
			{
				if (n->has_digest() == false)
				{
/*
 * get_file_digest() returns pointer to static memory so we
 * must use strdup() to save it.
 */
					gchar *tmp = get_file_digest(n->name);
					if (!tmp)
						return;

					n->digest = strdup(tmp);
					n->got_digest(true);
#ifdef DEBUG
					std::cerr << "Got digest of \"" << n->name << "\" at current node: " << n->digest << std::endl;
#endif
				}

/*
 * Don't need to strdup() this one because either we
 * will find that we don't need to keep it (cause the
 * hash is already in our bucket of digests), or we will
 * be calling strdup() later to save it at the end of
 * the bucket.
 */
				gchar *cur_digest = get_file_digest(name);

				if (!cur_digest)
					return;

#ifdef DEBUG
				std::cerr << "Got digest of current file \"" << name << "\": " << cur_digest << std::endl;
#endif

				if (!memcmp(cur_digest, n->digest, DIGEST_SIZE))
				{
					if (n->been_added() == false)
					{
#ifdef DEBUG
						std::cerr << "Adding duplicate file to linked list" << std::endl;
#endif
						this->add_dup_file(n->name, n->digest);
					}

#ifdef DEBUG
					std::cerr << "Adding duplicate file to linked list" << std::endl;
#endif
					this->add_dup_file(name, cur_digest);

					break;
				}
				else
				{
/*
 * O(N) check of our bucket of digests to see if this
 * hash is already in there. If not, save this one
 * at the end of the bucket.
 */
#ifdef DEBUG
					std::cerr << "Searching bucket for matching digest" << std::endl;
#endif
					if (n->nr_items_bucket() > 0)
					{
						gint i;
						gint nr_bucket = n->nr_items_bucket();
						bool is_dup = false;
						gint idx;

						if (n->bucket_contains(cur_digest, DIGEST_SIZE))
						{
#ifdef DEBUG
							std::cerr << "Found match in bucket. Inserting duplicate file to linked list" << std::endl;
#endif
							this->add_dup_file(name, cur_digest);
							is_dup = true;
						}

						if (is_dup == false)
						{
#ifdef DEBUG
							std::cerr << "No match in bucket. Adding file to bucket" << std::endl;
#endif
							fNode _node;
							_node.name = strdup(name);
							_node.digest = strdup(cur_digest);

							n->add_to_bucket(_node);
							return;
						}
					}
					else /* n->nr_items_bucket() == 0 */
					{
#ifdef DEBUG
						std::cerr << "Adding first file to bucket" << std::endl;
#endif
						fNode _node;
						_node.name = strdup(name);
						_node.digest = strdup(cur_digest);

						n->add_to_bucket(_node);
						return;
					}
				} /* cur_digest != n->digest */
			} /* size == n->size */
		} /* while (true) */
	}

	void show_duplicates(void)
	{
#ifdef DEBUG
		std::cerr << "Showing list of duplicate files" << std::endl;
#endif
		for (std::map<gchar *,std::list<dNode> >::iterator map_it = this->dup_list.begin(); map_it != this->dup_list.end(); ++map_it)
		{
			std::cerr << "** [" << map_it->first << "] **\n" << std::endl;
			for (std::list<dNode>::iterator node_it = map_it->second.begin(); node_it != map_it->second.end(); ++node_it)
			{
				std::cerr << node_it->name << std::endl;
			}

			std::cerr << "\n\n\n";
		}

#ifdef DEBUG
		for (std::map<gchar *,std::list<dNode> >::iterator map_it = this->dup_list.begin(); map_it != this->dup_list.end(); ++map_it)
			std::cerr << map_it->first << std::endl;
#endif
	}

	private:

	void add_dup_file(gchar *name, gchar *digest)
	{
		dNode node;

		node.name = strdup(name);

		for (std::map<gchar *,std::list<dNode> >::iterator map_it = this->dup_list.begin(); map_it != this->dup_list.end(); ++map_it)
		{
			if (!memcmp(digest, map_it->first, DIGEST_SIZE))
			{
				map_it->second.push_back(node);
				return;
			}
		}

		std::list<dNode> new_list;

		new_list.push_back(node);
		this->dup_list[digest] = new_list;

		return;
	}

	fNode *root;
	std::map<gchar *,std::list<dNode> > dup_list;
};

fTree::fTree(void)
{
	this->nr_nodes = 0;
	this->root = NULL;
}

fTree::~fTree(void)
{
	this->dup_list.clear();

	if (this->root)
	{
		fNode *node = this->root;
		fNode *parent = NULL;

		while (true)
		{
			if (!node->left && !node->right)
			{
				parent = node->parent;

				if (parent)
				{
					if (parent->left == node)
						parent->left = NULL;
					else
						parent->right = NULL;
				}

				free(node);

				if (!parent)
					break;

				node = parent;

				continue;
			}

			if (node->left)
			{
				while (node->left)
				{
					node = node->left;
				}
			}

			if (node->right)
			{
				node = node->right;
			}
		}
	} /* if this->root */
}

static fTree *tree;

static void
init_openssl(void)
{
	OPENSSL_config(NULL);
	OpenSSL_add_all_digests();
}

#define READ_BLOCK 4096

#define __ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))
static char const hexchars[17] = "0123456789abcdef";

gchar *
get_file_digest(gchar *path)
{
	struct stat statb;
	unsigned char *buffer = NULL;
	gsize toread;
	ssize_t n;
	EVP_MD_CTX *ctx;
	static unsigned char __digest[__ALIGN_SIZE(EVP_MAX_MD_SIZE + 1)];
	static unsigned char __hex[__ALIGN_SIZE(EVP_MAX_MD_SIZE * 2 + 1)];
	guint dlen = 0;
	gint fd = -1;

	lstat(path, &statb);

	memset(__digest, 0, DIGEST_SIZE / 2);
	memset(__hex, 0, DIGEST_SIZE);

	if ((fd = open(path, O_RDONLY)) < 0)
	{
		switch(errno)
		{
			case EPERM:
				std::cerr << "No permission to open \"" << path << "\"" << std::endl;
				break;
			default:
				std::cerr << "Failed to open \"" << path << "\" " << strerror(errno) << std::endl;
		}

		return NULL;
	}

	buffer = (unsigned char *)calloc(__ALIGN_SIZE(statb.st_size+1), 1);

	toread = statb.st_size;

	if (!(ctx = EVP_MD_CTX_create()))
	{
		std::cerr << "get_file_digest: failed to create MD CTX" << std::endl;
		goto fail;
	}

	if (1 != EVP_DigestInit_ex(ctx, DIGEST(), NULL))
	{
		std::cerr << "get_file_digest: failed to initialise MD CTX" << std::endl;
		goto fail;
	}

	while (toread > 0 && (n = read(fd, buffer, READ_BLOCK)))
	{
		if (n < 0)
		{
			if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
				continue;
			else
			{
				std::cerr << "get_file_digest: failed to read from \"" << path << "\"" << std::endl;
				goto fail;
			}
		}

		buffer[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, buffer, n))
		{
			std::cerr << "get_file_digest: failed to update hash digest" << std::endl;
			goto fail;
		}

		toread -= n;
	}

	if (1 != EVP_DigestFinal_ex(ctx, __digest, &dlen))
	{
		std::cerr << "get_file_digest: failed to finalise hash digest" << std::endl;
		goto fail;
	}

	EVP_MD_CTX_destroy(ctx);
	free(buffer);

	gint i;
	gint k;

/*
 * Hexlify the digest.
 */
	for (i = 0, k = 0; i < (gint)dlen; ++i)
	{
		__hex[k++] = hexchars[((__digest[i] >> 4) & 0xf)];
		__hex[k++] = hexchars[(__digest[i] & 0xf)];
	}

	__hex[k] = 0;

	close(fd);
	fd = -1;
	return (gchar *)__hex;

	fail:

	close(fd);
	fd = -1;
	free(buffer);
	EVP_MD_CTX_destroy(ctx);
	return NULL;
}

static gint
scan_files(gchar *dir)
{
	gsize len = strlen(dir);
	gchar *p = (dir + len);
	struct stat statb;
	DIR *dirp;
	struct dirent *dinf;

	if (*(p-1) != '/')
	{
		*p++ = '/';
		*p = 0;
		++len;
	}

	std::cerr << "Scanning directory \"" << dir << "\"" << std::endl;
	dirp = fdopendir(open(dir, O_DIRECTORY));

	assert(dirp);

	while ((dinf = readdir(dirp)))
	{
		if (!strcmp(".", dinf->d_name) ||
			!strcmp("..", dinf->d_name) ||
			dinf->d_name[0] == '.')
			continue;

		strcpy(p, dinf->d_name);
		lstat(dir, &statb);

		if (S_ISDIR(statb.st_mode))
		{
			scan_files(dir);
		}
		else
		if (S_ISREG(statb.st_mode))
		{
#ifdef DEBUG
			std::cerr << "Inserting \"" << dir << "\" into binary tree" << std::endl;
#endif
			tree->insert_file(dir);
		}
	}

	closedir(dirp);

	*p = 0;
	return 0;
}

static void
catch_sigint(int signo)
{
	if (signo != SIGINT)
		return;

	siglongjmp(__root_env__, 1);
}

static void
__attribute__((constructor)) __pollux_init(void)
{
	memset(&sigint_new, 0, sizeof(sigint_new));

	sigint_new.sa_handler = catch_sigint;
	sigint_new.sa_flags = 0;

	if (sigaction(SIGINT, &sigint_old, &sigint_new) < 0)
	{
		std::cerr << "__pollux_init: failed to set signal handler for SIGINT" << std::endl;
		goto fail;
	}

	return;

	fail:
	exit(EXIT_FAILURE);
}

void
on_digest_select(GtkWidget *widget, gpointer data)
{
	if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(widget)) == FALSE)
		return;

	struct Digest *dgst_ptr = NULL;
/*
 * Iterate over the linked list of struct Digest objects and
 * change those that != WIDGET to FALSE.
 */
	for (GList *list_iter = g_list_first(list_digests); list_iter; list_iter = list_iter->next)
	{
		dgst_ptr = (struct Digest *)list_iter->data;

		if (!dgst_ptr)
		{
			std::cerr << "*** list_iter->data is NULL ***" << std::endl;
			continue;
		}

		if (dgst_ptr->item == widget)
			continue;

		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(dgst_ptr->item), FALSE);
	}
}

void
create_menu_bar(void)
{
	menu_bar = gtk_menu_bar_new();
	item_file = gtk_menu_item_new_with_label("File");
	file_menu = gtk_menu_new();
	item_file_quit = gtk_menu_item_new_with_label("Quit");

	gtk_menu_item_set_submenu(GTK_MENU_ITEM(item_file), file_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), item_file_quit);

	options_menu = gtk_menu_new();
	item_options = gtk_menu_item_new_with_label("Options");
	digests_menu = gtk_menu_new();
	item_digests = gtk_menu_item_new_with_label("Digests");

	gtk_menu_item_set_submenu(GTK_MENU_ITEM(item_options), options_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(options_menu), item_digests);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(item_digests), digests_menu);

	list_digests = NULL;

	for (gint i = 0; i < NR_DIGESTS; ++i)
	{
		menu_digests[i].item = gtk_check_menu_item_new_with_label(menu_digests[i].name);

		if (menu_digests[i].type == __DEFAULT_DIGEST)
			gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_digests[i].item), TRUE);

		g_signal_connect(menu_digests[i].item, "toggled", G_CALLBACK(on_digest_select), NULL);
		gtk_menu_shell_append(GTK_MENU_SHELL(digests_menu), menu_digests[i].item);

		list_digests = g_list_append(list_digests, (gpointer)&menu_digests[i]);
	}

	gtk_menu_shell_append(GTK_MENU_SHELL(menu_bar), item_file);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu_bar), item_options);

	gtk_grid_attach(GTK_GRID(grid), menu_bar, 0, 0, 1, 1);

	return;
}


void
create_window(void)
{
	window = gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window), PROG_NAME " v"POLLUX_BUILD);
	gtk_window_set_default_size(GTK_WINDOW(window), WIN_DEFAULT_WIDTH, WIN_DEFAULT_HEIGHT);

	grid = gtk_grid_new();
	gtk_grid_set_column_spacing(GTK_GRID(grid), (guint)2);

	create_menu_bar();

	gtk_container_add(GTK_CONTAINER(window), grid);

/*
 * Load and keep our application icon in a pixbuf.
 */
	GError *error = NULL;

#define APP_LOGO_WIDTH 240
#define APP_LOGO_HEIGHT 240

	icon_pixbuf = gdk_pixbuf_new_from_file_at_size(
			POLLUX_LOGO,
			APP_LOGO_WIDTH,
			APP_LOGO_HEIGHT,
			&error);

	if (error)
	{
		g_error("Error loading application icon: (%s)\n", error->message);
		g_error_free(error);
	}

	gtk_window_set_icon(GTK_WINDOW(window), icon_pixbuf);
	g_object_unref(G_OBJECT(icon_pixbuf));

	const gchar *authors[] = PROG_AUTHORS;
	const gchar *title = "About " PROG_NAME;

	gtk_show_about_dialog(
			GTK_WINDOW(window),
			"program-name", PROG_NAME,
			"logo", icon_pixbuf,
			"title", title,
			"version", POLLUX_BUILD,
			"comments", PROG_COMMENTS,
			"authors", authors,
			"website", PROG_WEBSITE,
			NULL);
#if 0
	about = gtk_about_dialog_new();
	gtk_about_dialog_set_program_name(GTK_ABOUT_DIALOG(about), PROG_NAME);
	gtk_about_dialog_set_version(GTK_ABOUT_DIALOG(about), POLLUX_BUILD);
	gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG(about), PROG_COMMENTS);
	gtk_about_dialog_set_authors(GTK_ABOUT_DIALOG(about), authors);
	gtk_about_dialog_set_logo(GTK_ABOUT_DIALOG(about), icon_pixbuf);
#endif

	status_bar = gtk_statusbar_new();
	guint ctx_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(status_bar), (const gchar *)"Ready to scan...");
	gtk_statusbar_push(GTK_STATUSBAR(status_bar), ctx_id, (const gchar *)"Ready to scan...");
	
	button_start_scan = gtk_button_new_with_label("Scan");

/* gtk_grid_attach(GtkGrid *grid, GtkWidget *widget, gint left, gint top, gint width, gint height); */
	gtk_grid_attach(GTK_GRID(grid), button_start_scan, 10, 30, 2, 4);
	gtk_grid_attach(GTK_GRID(grid), status_bar, 0, 250, 8, 100);
	gtk_widget_show_all(window);

	return;
}

int
main(int argc, char *argv[])
{
	struct stat statb;
	gint status;

	app = gtk_application_new(PROG_NAME_DBUS, G_APPLICATION_FLAGS_NONE);
	g_signal_connect(app, "activate", G_CALLBACK(create_window), NULL);
	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(G_OBJECT(app));
#if 0
	tree = new fTree();

	std::cerr << "Pollux build " << POLLUX_BUILD << " (written in C++)" << std::endl;

	if (argc < 2)
	{
		std::cerr << PROG_NAME << " <directory>" << std::endl;
		exit(EXIT_FAILURE);
	}


	lstat(argv[1], &statb);

	if (!S_ISDIR(statb.st_mode))
	{
		std::cerr << "\"" << argv[1] << "\" is not a directory!" << std::endl;
		goto fail;
	}

	if (sigsetjmp(__root_env__, 1) != 0)
	{
		std::cerr << "Caught user-generated signal" << std::endl;
		goto out_release_mem;
	}

	init_openssl();

	std::cerr << "Starting scan in directory " << argv[1] << std::endl;

	if (scan_files(argv[1]) == -1)
		goto fail;

	tree->show_duplicates();

	out_release_mem:
#endif

	delete tree;
	return 0;

	fail:
	delete tree;
	return -1;
}
