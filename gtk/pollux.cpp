#include <iostream>
#include <list>
#include <map>
#include <gtk/gtk.h>

class fNode:
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
class dNode:
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
class dList:
{
	public:

	gchar *digest;
	gsize nr_nodes;
	dNode *head;

	dList();
};

dList::dList(void)
{
	this->digest = NULL;
	this->nr_nodes = 0;
	this->head = NULL;
}

class fTree:
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
							_node->digest = __dup_digest(cur_digest);

							n->bucket.push_back(_node);
							n->nr_bucket += 1;
						}
					}
				}
			}
		}
	}

	private:

	fNode *root;
	std::map<char *,int> hash_idx_map;
	std::list<dList> dup_list;
};

fTree::FTree(void)
{
	this->nr_nodes = 0;
	this->root = NULL;
}
