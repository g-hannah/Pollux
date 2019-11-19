#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <list>
#include <map>
#include <gtk/gtk.h>

#define PROG_NAME "Pollux"

enum
{
	DIGEST_MD5,
	DIGEST_SHA256,
	DIGEST_SHA512,
	NR_DIGESTS
};

struct plx_ctx;

static struct plx_ctx plx_ctx;
static gsize get_digest_size_hex(gint type);

class fNode
{
	gchar *digest;
	gchar *name;
	gsize size;
	fNode *left;
	fNode *right;
	bool have_digest;
	bool added;
	std::list<fNode> bucket;
	gsize nr_bucket;

	public:

	fNode();
};

fNode::fNode(void)
{
	this->digest = NULL;
	this->name = NULL;
	this->size = 0;
	this->left = NULL;
	this->right = NULL;
	this->have_digest = false;
	this->added = false;
	this->nr_bucket = 0
}

/*
 * Duplicate file node.
 */
class dNode
{
	public:

	gchar *name;
	dNode *next;
	dNode *prev;

	dNode();
};

dNode::dNode(void)
{
	this->name = NULL;
	this->next = NULL;
	this->prev = NULL;
}

/*
 * Linked list of digests, containing
 * a head pointer to linked list of
 * all the files that have this digest.
 */
class dList
{
	public:

	gchar *digest;
	gsize nr_nodes;
	std::list files;

	dList();
};

dList::dList(void)
{
	this->digest = NULL;
	this->nr_nodes = 0;
	this->head = NULL;
}

class fTree
{
	public:

	gsize nr_nodes;

	fTree();

	void insert_file(gchar *name)
	{
		struct statb statb;
		gsize size;

		lstat(name, &statb);
		size = statb.st_size;

		if (!this->root)
		{
			this->root = new fNode();
			this->root->name = strdup(name);
			this->root->size = size;
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
					this->nr_nodes += 1;

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
					this->nr_nodes += 1;
				}
				else
				{
					n = n->right;
					continue;
				}
			}
			else
			{
				if (n->have_digest == false)
				{
					n->digest = get_file_digest(n->name);
					n->have_digest = true;
				}

				gchar *cur_digest = get_file_digest(name);

				if (!memcmp(cur_digest, n->digest, digest_size))
				{
					if (n->added == false)
						this->add_dup_file(n->name, n->digest);

					this->add_dup_file(name, cur_digest);
				}
				else
				{
					if (n->nr_bucket > 0)
					{
						gint i;
						gint nr_bucket = n->nr_bucket;
						bool is_dup = false;

						for (std::list<fNode>::iterator it = n->bucket.begin(); it != n->bucket.end(); ++it)
						{
							if (!memcmp(cur_digest, it->digest, digest_size))
							{
								this->add_dup_file(name, cur_digest);
								is_dup = true;
								break;
							}
						}

						if (is_dup == false)
						{
							fNode *_node = new fNode();
							_node->name = strdup(name);
							_node->digest = strdup(cur_digest);

							n->bucket.push_back(_node);
							n->nr_bucket += 1;
						}
					}
				}
			}
		}
	}

	void destroy_all(void)
	{
		std::list<dList>::iterator it = this->dup_list.begin();

		for (; it != this->dup_list.end(); ++it)
		{
			if (it->digest)
				free(it->digest);

			std::list<dNode>::iterator _it = it->files.begin();

			for (; _it != it->files.end(); ++_it)
			{
				if (_it->name)
					free(_it->name);
			}

			_it->files.clear();
		}

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

		this->hash_idx_map.clear();
	}

	private:

	void add_dup_file(gchar *name, gchar *digest)
	{
		gint hash_list_idx;
		guint map_size;

		map_size = this->hash_idx_map.size();

		if (!map_size)
		{
			dList *list = new dList();
			dNode *node = new dNode();
			this->dup_list.push_back(list);

			node->name = strdup(name);
			list->files.push_back(node);

			this->hash_idx_map[digest] = map_size;
		}
		else
		{
			std::map<char *,int>::iterator it;

			it = this->hash_idx_map.find(digest);

			if (it)
			{
				hash_list_idx = it->second;
				std::list<dList>::iterator _it = this->dup_list.begin();
				gint _i = 0;

				while (_i++ < hash_list_idx)
					++_it;

				dNode *node = new dNode();
				node->name = strdup(name);

				_it->files.push_back(node);
			}
			else
			{
				this->hash_idx_map[digest] = map_size;
			}
		}
	}

	fNode *root;
	std::map<char *,int> hash_idx_map;
	std::list<dList> dup_list;
};

fTree::fTree(void)
{
	this->nr_nodes = 0;
	this->root = NULL;
}

struct plx_ctx
{
	gint digest_type;
	fTree *tree;
};

static void release_mem(void)
{
	fTree *tree = plx_ctx.tree;

	if (tree)
		tree->destroy_all();

	return;
}

gsize
get_digest_size_ascii(gint type)
{
	switch(type)
	{
		case DIGEST_SHA256:
			return (gsize)64;
			break;
		case DIGEST_SHA512:
			return (gsize)128;
			break;
		default:
			return (gsize)32;
			break;
	}

	assert(0);
}

static gint
scan_files(gchar *dir)
{
	gsize len = strlen(dir);
	gchar *p = (dir + len);
	struct stat statb;
	DIR *dirp;
	struct dirent *dinf;
	fTree *tree = plx_ctx.tree;

	if (*(p-1) != '/')
	{
		*p++ = '/';
		*p = 0;
		++len;
	}

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
			tree->insert_file(dir);
		}
	}

	*p = 0;
	return 0;
}

int
main(int argc, char *argv[])
{
	struct stat statb;

	if (argc < 2)
	{
		std::cerr << PROG_NAME << " <directory>" << std::endl;
		exit(EXIT_FAILURE);
	}

	memset(&plx_ctx, 0, sizeof(plx_ctx));
	plx_ctx.tree = new fTree();

	atexit(release_mem);

	lstat(argv[1], &statb);

	if (!S_ISDIR(statb.st_mode))
	{
		std::cerr << "\"" << argv[1] << "\" is not a directory!" << std::endl;
		goto fail;
	}

	if (scan_files(argv[1]) == -1)
		goto fail;

	fail:
	exit(EXIT_FAILURE);
}


























