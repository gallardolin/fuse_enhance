/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/exportfs.h>
#include <linux/delay.h>


MODULE_AUTHOR("Miklos Szeredi <miklos@szeredi.hu>");
MODULE_DESCRIPTION("Filesystem in Userspace");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static struct kmem_cache *fuse_inode_cachep;
struct list_head fuse_conn_list;
DEFINE_MUTEX(fuse_mutex);

static int set_global_limit(const char *val, struct kernel_param *kp);

unsigned max_user_bgreq;
module_param_call(max_user_bgreq, set_global_limit, param_get_uint,
		  &max_user_bgreq, 0644);
__MODULE_PARM_TYPE(max_user_bgreq, "uint");
MODULE_PARM_DESC(max_user_bgreq,
 "Global limit for the maximum number of backgrounded requests an "
 "unprivileged user can set");

unsigned max_user_congthresh;
module_param_call(max_user_congthresh, set_global_limit, param_get_uint,
		  &max_user_congthresh, 0644);
__MODULE_PARM_TYPE(max_user_congthresh, "uint");
MODULE_PARM_DESC(max_user_congthresh,
 "Global limit for the maximum congestion threshold an "
 "unprivileged user can set");

#define FUSE_SUPER_MAGIC 0x65735546

#define FUSE_DEFAULT_BLKSIZE 512

/** Maximum number of outstanding background requests */
#define FUSE_DEFAULT_MAX_BACKGROUND 12

/** Congestion starts at 75% of maximum */
#define FUSE_DEFAULT_CONGESTION_THRESHOLD (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4)

struct fuse_mount_data {
	int fd;
	unsigned rootmode;
	kuid_t user_id;
	kgid_t group_id;
	unsigned fd_present:1;
	unsigned rootmode_present:1;
	unsigned user_id_present:1;
	unsigned group_id_present:1;
	unsigned flags;
	unsigned max_read;
	unsigned blksize;
	char *mount_path;
	int iscache;
	int support_partial_upload;
};

struct fuse_forget_link *fuse_alloc_forget(void)
{
	return kzalloc(sizeof(struct fuse_forget_link), GFP_KERNEL);
}

static struct inode *fuse_alloc_inode(struct super_block *sb)
{
	struct inode *inode;
	struct fuse_inode *fi;

	inode = kmem_cache_alloc(fuse_inode_cachep, GFP_KERNEL);
	if (!inode)
		return NULL;

	fi = get_fuse_inode(inode);
	fi->i_time = 0;
	fi->nodeid = 0;
	fi->nlookup = 0;
	fi->attr_version = 0;
	fi->writectr = 0;
	fi->orig_ino = 0;
	fi->state = 0;
	INIT_LIST_HEAD(&fi->write_files);
	INIT_LIST_HEAD(&fi->queued_writes);
	INIT_LIST_HEAD(&fi->writepages);
	init_waitqueue_head(&fi->page_waitq);
	fi->forget = fuse_alloc_forget();
	if (!fi->forget) {
		kmem_cache_free(fuse_inode_cachep, inode);
		return NULL;
	}

	return inode;
}

static void fuse_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(fuse_inode_cachep, inode);
}

static void fuse_destroy_inode(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	BUG_ON(!list_empty(&fi->write_files));
	BUG_ON(!list_empty(&fi->queued_writes));
	kfree(fi->forget);
	call_rcu(&inode->i_rcu, fuse_i_callback);
}

static void fuse_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (inode->i_sb->s_flags & MS_ACTIVE) {
		struct fuse_conn *fc = get_fuse_conn(inode);
		struct fuse_inode *fi = get_fuse_inode(inode);
		fuse_queue_forget(fc, fi->forget, fi->nodeid, fi->nlookup);
		fi->forget = NULL;
	}
}

static int fuse_remount_fs(struct super_block *sb, int *flags, char *data)
{
	if (*flags & MS_MANDLOCK)
		return -EINVAL;

	return 0;
}

/*
 * ino_t is 32-bits on 32-bit arch. We have to squash the 64-bit value down
 * so that it will fit.
 */
static ino_t fuse_squash_ino(u64 ino64)
{
	ino_t ino = (ino_t) ino64;
	if (sizeof(ino_t) < sizeof(u64))
		ino ^= ino64 >> (sizeof(u64) - sizeof(ino_t)) * 8;
	return ino;
}

void fuse_change_attributes_common(struct inode *inode, struct fuse_attr *attr,
				   u64 attr_valid)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	fi->attr_version = ++fc->attr_version;
	fi->i_time = attr_valid;

	inode->i_ino     = fuse_squash_ino(attr->ino);
	inode->i_mode    = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	set_nlink(inode, attr->nlink);
	inode->i_uid     = make_kuid(&init_user_ns, attr->uid);
	inode->i_gid     = make_kgid(&init_user_ns, attr->gid);
	inode->i_blocks  = attr->blocks;
	inode->i_atime.tv_sec   = attr->atime;
	inode->i_atime.tv_nsec  = attr->atimensec;
	inode->i_mtime.tv_sec   = attr->mtime;
	inode->i_mtime.tv_nsec  = attr->mtimensec;
	inode->i_ctime.tv_sec   = attr->ctime;
	inode->i_ctime.tv_nsec  = attr->ctimensec;

	if (attr->blksize != 0)
		inode->i_blkbits = ilog2(attr->blksize);
	else
		inode->i_blkbits = inode->i_sb->s_blocksize_bits;

	/*
	 * Don't set the sticky bit in i_mode, unless we want the VFS
	 * to check permissions.  This prevents failures due to the
	 * check in may_delete().
	 */
	fi->orig_i_mode = inode->i_mode;
	if (!(fc->flags & FUSE_DEFAULT_PERMISSIONS))
		inode->i_mode &= ~S_ISVTX;

	fi->orig_ino = attr->ino;

	attr->size = (inode->i_size > 0)? inode->i_size: attr->size;
}

void fuse_change_attributes(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	loff_t oldsize;
	struct timespec old_mtime;

	spin_lock(&fc->lock);
	if ((attr_version != 0 && fi->attr_version > attr_version) ||
	    test_bit(FUSE_I_SIZE_UNSTABLE, &fi->state)) {
		spin_unlock(&fc->lock);
		return;
	}

	old_mtime = inode->i_mtime;
	fuse_change_attributes_common(inode, attr, attr_valid);

	/*
	if(attr->size == 0 && inode->i_ino != 0)
	{
		printk("[%s] size@%llu inode@%lld @%ld\n"
		, __func__, attr->size, inode->i_size, inode->i_ino);
		dump_stack();
	}
	*/

	oldsize = inode->i_size;
	i_size_write(inode, attr->size);
	spin_unlock(&fc->lock);

	if (S_ISREG(inode->i_mode)) {
		bool inval = false;

		if (oldsize != attr->size) {
			truncate_pagecache(inode, attr->size);
			inval = true;
		} else if (fc->auto_inval_data) {
			struct timespec new_mtime = {
				.tv_sec = attr->mtime,
				.tv_nsec = attr->mtimensec,
			};

			/*
			 * Auto inval mode also checks and invalidates if mtime
			 * has changed.
			 */
			if (!timespec_equal(&old_mtime, &new_mtime))
				inval = true;
		}

		if (inval)
			invalidate_inode_pages2(inode->i_mapping);
	}
}

static void fuse_init_inode(struct inode *inode, struct fuse_attr *attr)
{
	inode->i_mode = attr->mode & S_IFMT;
	inode->i_size = attr->size;
	if (S_ISREG(inode->i_mode)) {
		fuse_init_common(inode);
		fuse_init_file_inode(inode);
	} else if (S_ISDIR(inode->i_mode))
		fuse_init_dir(inode);
	else if (S_ISLNK(inode->i_mode))
		fuse_init_symlink(inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		fuse_init_common(inode);
		init_special_inode(inode, inode->i_mode,
				   new_decode_dev(attr->rdev));
	} else
		BUG();
}

int fuse_inode_eq(struct inode *inode, void *_nodeidp)
{
	u64 nodeid = *(u64 *) _nodeidp;
	if (get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

static int fuse_inode_set(struct inode *inode, void *_nodeidp)
{
	u64 nodeid = *(u64 *) _nodeidp;
	get_fuse_inode(inode)->nodeid = nodeid;
	return 0;
}

struct inode *fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version)
{
	struct inode *inode;
	struct fuse_inode *fi;
	struct fuse_conn *fc = get_fuse_conn_super(sb);

 retry:
	inode = iget5_locked(sb, nodeid, fuse_inode_eq, fuse_inode_set, &nodeid);
	if (!inode)
		return NULL;

	if ((inode->i_state & I_NEW)) {
		inode->i_flags |= S_NOATIME|S_NOCMTIME;
		inode->i_generation = generation;
		inode->i_data.backing_dev_info = &fc->bdi;
		fuse_init_inode(inode, attr);
		unlock_new_inode(inode);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		/* Inode has changed type, any I/O on the old should fail */
		make_bad_inode(inode);
		iput(inode);
		goto retry;
	}

	fi = get_fuse_inode(inode);
	spin_lock(&fc->lock);
	fi->nlookup++;
	spin_unlock(&fc->lock);
	fuse_change_attributes(inode, attr, attr_valid, attr_version);

	return inode;
}

int fuse_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len)
{
	struct inode *inode;
	pgoff_t pg_start;
	pgoff_t pg_end;

	inode = ilookup5(sb, nodeid, fuse_inode_eq, &nodeid);
	if (!inode)
		return -ENOENT;

	fuse_invalidate_attr(inode);
	if (offset >= 0) {
		pg_start = offset >> PAGE_CACHE_SHIFT;
		if (len <= 0)
			pg_end = -1;
		else
			pg_end = (offset + len - 1) >> PAGE_CACHE_SHIFT;
		invalidate_inode_pages2_range(inode->i_mapping,
					      pg_start, pg_end);
	}
	iput(inode);
	return 0;
}

static void fuse_umount_begin(struct super_block *sb)
{
	fuse_abort_conn(get_fuse_conn_super(sb));
}

static void fuse_send_destroy(struct fuse_conn *fc)
{
	struct fuse_req *req = fc->destroy_req;
	if (req && fc->conn_init) {
		fc->destroy_req = NULL;
		req->in.h.opcode = FUSE_DESTROY;
		req->force = 1;
		req->background = 0;
		fuse_request_send(fc, req);
		fuse_put_request(fc, req);
	}
}

static void fuse_bdi_destroy(struct fuse_conn *fc)
{
	if (fc->bdi_initialized)
		bdi_destroy(&fc->bdi);
}

void fuse_conn_kill(struct fuse_conn *fc)
{
	spin_lock(&fc->lock);
	fc->connected = 0;
	fc->blocked = 0;
	fc->initialized = 1;
	spin_unlock(&fc->lock);
	/* Flush all readers on this fs */
	kill_fasync(&fc->fasync, SIGIO, POLL_IN);
	wake_up_all(&fc->waitq);
	wake_up_all(&fc->blocked_waitq);
	wake_up_all(&fc->reserved_req_waitq);
	if (fc->mount_path)
		kfree(fc->mount_path);
	if (fc->mount_path_translated)
		kfree(fc->mount_path_translated);
	if (fc->async_wq)
		destroy_workqueue(fc->async_wq);
	if(fc->shared_bucket_list)
		free_shared_bucket_list(fc->shared_bucket_list);
}
EXPORT_SYMBOL_GPL(fuse_conn_kill);

static void fuse_put_super(struct super_block *sb)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);

	fuse_send_destroy(fc);

	fuse_conn_kill(fc);
	mutex_lock(&fuse_mutex);
	list_del(&fc->entry);
	fuse_ctl_remove_conn(fc);
	mutex_unlock(&fuse_mutex);
	fuse_bdi_destroy(fc);

	fuse_conn_put(fc);
}

static void convert_fuse_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr)
{
	stbuf->f_type    = FUSE_SUPER_MAGIC;
	stbuf->f_bsize   = attr->bsize;
	stbuf->f_frsize  = attr->frsize;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = attr->bfree;
	stbuf->f_bavail  = attr->bavail;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->ffree;
	stbuf->f_namelen = attr->namelen;
	/* fsid is left zero */
}

static int fuse_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct fuse_req *req;
	struct fuse_statfs_out outarg;
	int err, success = 0;

	if (!fuse_allow_current_process(fc)) {
		buf->f_type = FUSE_SUPER_MAGIC;
		return 0;
	}

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&outarg, 0, sizeof(outarg));
	req->in.numargs = 0;
	req->in.h.opcode = FUSE_STATFS;
	req->in.h.nodeid = get_node_id(dentry->d_inode);
	req->out.numargs = 1;
	req->out.args[0].size =
		fc->minor < 4 ? FUSE_COMPAT_STATFS_SIZE : sizeof(outarg);
	req->out.args[0].value = &outarg;

	if (fc->iscache && fc->mount_path)
	{
		char *buf_path = NULL, *path =NULL;
		struct file *cache_file = NULL;
		int need_free = 0;
		struct dentry *entry = dentry;
		if(entry == NULL)
		{
			entry = d_find_alias(dentry->d_inode);
			need_free = 1;

		}

		if(entry)
		{
			char *real_path = NULL;
			path = fuse_prepare_path(fc, entry, buf_path);
			if(!path)
			{
				printk("[%s] file@%s\n", __func__, entry->d_iname);
				goto drop_path;
			}
			
			real_path = path_translate(path);
			if(!real_path)
			{
				printk("[%s] file@%s path@%s\n", __func__, entry->d_iname, path);
				goto drop_path;
			}

			if (S_ISDIR(dentry->d_inode->i_mode))
				cache_file = filp_open(real_path, O_DIRECTORY, 0);
			else
				cache_file = filp_open(real_path, O_RDONLY, 0);

			if (IS_ERR(cache_file))
			{
				printk("[%s] file@%s path@%s real_path@%s\n", __func__, entry->d_iname, path, real_path);
				goto free_cache_normal;
			}

			req->out.h.error = cache_file->f_dentry->d_sb->s_op->statfs(cache_file->f_dentry, buf);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf_path)
				kfree(buf_path);

			if(need_free)
				dput(entry);
		}
		else
			printk("[%s] no entry\n", __func__);
	}

	if(success == 0)
	{
		fuse_request_send(fc, req);
	}

	err = req->out.h.error;
	if (!err)
	{
		if(!success)
			convert_fuse_statfs(buf, &outarg.st);
	}
	fuse_put_request(fc, req);
	return err;
}

enum {
	OPT_FD,
	OPT_ROOTMODE,
	OPT_USER_ID,
	OPT_GROUP_ID,
	OPT_DEFAULT_PERMISSIONS,
	OPT_ALLOW_OTHER,
	OPT_MAX_READ,
	OPT_BLKSIZE,
	OPT_MOUNT_PATH,
	OPT_ISCACHE,
	OPT_SUPPORT_PARTIAL,
	OPT_ERR
};

static const match_table_t tokens = {
	{OPT_FD,			"fd=%u"},
	{OPT_ROOTMODE,			"rootmode=%o"},
	{OPT_USER_ID,			"user_id=%u"},
	{OPT_GROUP_ID,			"group_id=%u"},
	{OPT_DEFAULT_PERMISSIONS,	"default_permissions"},
	{OPT_ALLOW_OTHER,		"allow_other"},
	{OPT_MAX_READ,			"max_read=%u"},
	{OPT_BLKSIZE,			"blksize=%u"},
	{OPT_MOUNT_PATH,		"mount_path=%s"},
	{OPT_ISCACHE,		    "iscache"},
	{OPT_SUPPORT_PARTIAL,   "partial_upload"},
	{OPT_ERR,			NULL}
};

static int parse_fuse_opt(char *opt, struct fuse_mount_data *d, int is_bdev)
{
	char *p;
	int length;
	memset(d, 0, sizeof(struct fuse_mount_data));
	d->max_read = ~0;
	d->blksize = FUSE_DEFAULT_BLKSIZE;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		int value;
		substring_t args[MAX_OPT_ARGS];
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case OPT_FD:
			if (match_int(&args[0], &value))
				return 0;
			d->fd = value;
			d->fd_present = 1;
			break;

		case OPT_ROOTMODE:
			if (match_octal(&args[0], &value))
				return 0;
			if (!fuse_valid_type(value))
				return 0;
			d->rootmode = value;
			d->rootmode_present = 1;
			break;

		case OPT_USER_ID:
			if (match_int(&args[0], &value))
				return 0;
			d->user_id = make_kuid(current_user_ns(), value);
			if (!uid_valid(d->user_id))
				return 0;
			d->user_id_present = 1;
			break;

		case OPT_GROUP_ID:
			if (match_int(&args[0], &value))
				return 0;
			d->group_id = make_kgid(current_user_ns(), value);
			if (!gid_valid(d->group_id))
				return 0;
			d->group_id_present = 1;
			break;

		case OPT_DEFAULT_PERMISSIONS:
			d->flags |= FUSE_DEFAULT_PERMISSIONS;
			break;

		case OPT_ALLOW_OTHER:
			d->flags |= FUSE_ALLOW_OTHER;
			break;

		case OPT_MAX_READ:
			if (match_int(&args[0], &value))
				return 0;
			d->max_read = value;
			break;

		case OPT_BLKSIZE:
			if (!is_bdev || match_int(&args[0], &value))
				return 0;
			d->blksize = value;
			break;

		case OPT_MOUNT_PATH:
			length = args[0].to - args[0].from + 1;
			d->mount_path = kmalloc(sizeof(char) * length, GFP_KERNEL);
			memset(d->mount_path, 0, length);
			memcpy(d->mount_path, args[0].from, length);
			break;

		case OPT_ISCACHE:
			 d->iscache = 1;
			 break;

		case OPT_SUPPORT_PARTIAL:
			d->support_partial_upload = 1;
			break;

		default:
			return 0;
		}
	}

	if (!d->fd_present || !d->rootmode_present ||
	    !d->user_id_present || !d->group_id_present)
		return 0;

	return 1;
}

static int fuse_show_options(struct seq_file *m, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct fuse_conn *fc = get_fuse_conn_super(sb);

	seq_printf(m, ",user_id=%u", from_kuid_munged(&init_user_ns, fc->user_id));
	seq_printf(m, ",group_id=%u", from_kgid_munged(&init_user_ns, fc->group_id));
	if (fc->flags & FUSE_DEFAULT_PERMISSIONS)
		seq_puts(m, ",default_permissions");
	if (fc->flags & FUSE_ALLOW_OTHER)
		seq_puts(m, ",allow_other");
	if (fc->max_read != ~0)
		seq_printf(m, ",max_read=%u", fc->max_read);
	if (sb->s_bdev && sb->s_blocksize != FUSE_DEFAULT_BLKSIZE)
		seq_printf(m, ",blksize=%lu", sb->s_blocksize);
	return 0;
}

void fuse_conn_init(struct fuse_conn *fc)
{
	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	mutex_init(&fc->inst_mutex);
	init_rwsem(&fc->killsb);
	atomic_set(&fc->count, 1);
	init_waitqueue_head(&fc->waitq);
	init_waitqueue_head(&fc->blocked_waitq);
	init_waitqueue_head(&fc->reserved_req_waitq);
	INIT_LIST_HEAD(&fc->pending);
	INIT_LIST_HEAD(&fc->processing);
	INIT_LIST_HEAD(&fc->io);
	INIT_LIST_HEAD(&fc->interrupts);
	INIT_LIST_HEAD(&fc->bg_queue);
	INIT_LIST_HEAD(&fc->entry);
	fc->forget_list_tail = &fc->forget_list_head;
	atomic_set(&fc->num_waiting, 0);
	fc->max_background = FUSE_DEFAULT_MAX_BACKGROUND;
	fc->congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD;
	fc->khctr = 0;
	fc->polled_files = RB_ROOT;
	fc->reqctr = 0;
	fc->blocked = 0;
	fc->initialized = 0;
	fc->attr_version = 1;
	fc->iscache = 0;

	get_random_bytes(&fc->scramble_key, sizeof(fc->scramble_key));
}
EXPORT_SYMBOL_GPL(fuse_conn_init);

void fuse_conn_put(struct fuse_conn *fc)
{
	if (atomic_dec_and_test(&fc->count)) {
		if (fc->destroy_req)
			fuse_request_free(fc->destroy_req);
		mutex_destroy(&fc->inst_mutex);
		fc->release(fc);
	}
}
EXPORT_SYMBOL_GPL(fuse_conn_put);

struct fuse_conn *fuse_conn_get(struct fuse_conn *fc)
{
	atomic_inc(&fc->count);
	return fc;
}
EXPORT_SYMBOL_GPL(fuse_conn_get);

static struct inode *fuse_get_root_inode(struct super_block *sb, unsigned mode)
{
	struct fuse_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.mode = mode;
	attr.ino = FUSE_ROOT_ID;
	attr.nlink = 1;
	return fuse_iget(sb, 1, 0, &attr, 0, 0);
}

struct fuse_inode_handle {
	u64 nodeid;
	u32 generation;
};

char* path_translate(char *path)
{
	char *nowptr = path;
	char *cache_path = kmalloc(strlen(path)+8, GFP_KERNEL);
	char *temp;
	int offset = 0, i;
	if (!cache_path)
		return NULL;

	memset(cache_path, 0, strlen(path)+8);
	for(i=0; i<3; i++) {
		nowptr = strchr(nowptr, '/');
		if (!nowptr)
			goto free_exit;
		nowptr++;
	}

	i = nowptr - path;
	strncpy(cache_path, path, i);
	offset += i;

	*(cache_path+offset) = '.';
	offset++;

	temp = nowptr;
	nowptr = strchr(nowptr, '/');
	if (nowptr) // non-root
	{
		nowptr++;
		i = nowptr-temp;
		strncpy(cache_path+offset, temp, i);
		offset += i;
		
		strncpy(cache_path+offset, "files/", strlen("files/"));
		offset += strlen("files/");
		strncpy(cache_path+offset, nowptr, strlen(nowptr));
	}
	else // root
	{
		nowptr = temp++;
		i = strlen(nowptr);
		strncpy(cache_path + offset, nowptr, i);
		offset += i;
		strncpy(cache_path + offset, "/files", strlen("/files"));
	}
free_exit:
	return cache_path;
}
/*
static char* xfs_path_to_cache(char *path)
{
	char *nowptr = path;
	int i = 3;

	for(i = 3; i > 0; i--)
		nowptr = strchr(nowptr, '/');
		if (!nowptr)
			return NULL;

	return nowptr;
}
*/
static struct dentry *fuse_get_dentry(struct super_block *sb,
				      struct fuse_inode_handle *handle)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct file *dfilp, *xfs_filp;
	struct inode *inode;
	struct dentry *entry, *xfs_dentry;
	struct fuse_entry_out outarg;
	struct qstr name;
	char *cPath, *buf;
	int err = -ESTALE, length, ret;
	int sleep_count;

	if (handle->nodeid == 0)
		goto out_err;

	inode = ilookup5(sb, handle->nodeid, fuse_inode_eq, &handle->nodeid);
	if (inode)
		goto inode_found;

	if (!fc->export_support)
		goto out_err;

	if (fc->iscache && fc->mount_path)
	{
		/* step 1. check if translated path cached
		 * step 2. open XFS with translated mount_path
		 * step 3. send file_op to get dentry
		 * step 5. get path from xattr
		 * step 6. open the path and then close
		 * step 7. following the normal route
		*/ 

		if (!fc->mount_path_translated)
			fc->mount_path_translated = path_translate(fc->mount_path);

		if (!fc->mount_path_translated)
		{
			printk("no translated path\n");
			goto normal_lookup;
		}

		dfilp = filp_open(fc->mount_path_translated, O_DIRECTORY, 0);
		if (IS_ERR(dfilp))
		{
			printk("[%s] path_translated@%s inodeID: %llu, gen: %u open translated failed: %ld\n"
				, __func__, fc->mount_path_translated, handle->nodeid, handle->generation, PTR_ERR(dfilp));
			goto normal_lookup;
		}

		if (!dfilp->f_op->get_dentry)
			goto close_d_normal;

		xfs_dentry = dfilp->f_op->get_dentry(dfilp, handle->nodeid, handle->generation);
		if (xfs_dentry == NULL)
		{
			printk("[%s] path_translated@%s inodeID: %llu, gen: %u get_dentry failed: NULL\n"
				, __func__, fc->mount_path_translated, handle->nodeid, handle->generation);
			goto close_d_normal;
		}
		if (IS_ERR(xfs_dentry))
		{
			printk("[%s] path_translated@%s inodeID: %llu, gen: %u get_dentry failed: %ld\n"
				, __func__, fc->mount_path_translated, handle->nodeid, handle->generation, PTR_ERR(xfs_dentry));
			goto close_d_normal;
		}
		if (xfs_dentry->d_inode->i_ino != handle->nodeid)
		{
			printk("[%s] path_translated@%s inodeID: %llu, gen: %u Inode ID not match: %lu\n"
				, __func__, fc->mount_path_translated, handle->nodeid, handle->generation, xfs_dentry->d_inode->i_ino);
			goto dput_normal;
		}

		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buf)
		{
			printk("[%s] path_translated@%s inodeID: %llu, gen: %u Inode ID not match: %lu no mem\n"
				, __func__, fc->mount_path_translated, handle->nodeid, handle->generation, xfs_dentry->d_inode->i_ino);
			goto dput_normal;
		}

		memset(buf, 0, PATH_MAX);
		length = strlen(fc->mount_path);
		strncpy(buf, fc->mount_path, length);
		cPath = buf + length;

		printk("[%s] length, %d cPath: %s name@%s id@%lu gen@%u buf@%s\n"
			, __func__
			, length, buf, xfs_dentry->d_iname, xfs_dentry->d_inode->i_ino
			, xfs_dentry->d_inode->i_generation, buf);
		ret = xfs_dentry->d_inode->i_op->getxattr(xfs_dentry, "user.whoami", (void *) cPath, PATH_MAX - length);
		if (ret < 0)
		{
			char *path_buf = NULL, *tmp_path = NULL;
			struct dentry *fuse_dentry = NULL;
			int success = 0;
			printk("[%s] path_translated@%s inodeID: %llu, gen: %u length, %d cPath: %s vfs_getxattr ret:%d\n"
				, __func__, fc->mount_path_translated, handle->nodeid, handle->generation
				, length, buf, ret);
			
			if(strcmp(xfs_dentry->d_iname, "/") == 0)
			{
				fuse_dentry = d_find_alias(xfs_dentry->d_inode);
				printk("[%s] fuse_dentry@%s\n", __func__, fuse_dentry->d_iname);
				if(strcmp(fuse_dentry->d_iname, "/") == 0)
					goto drop_path;
			}
			
			tmp_path = fuse_prepare_path(fc, (fuse_dentry)?fuse_dentry:xfs_dentry, path_buf);
			if(!tmp_path)
				goto drop_path;

			printk("[%s] cPath@%s buf@%s tmp_path@%s\n", __func__, cPath, buf, tmp_path);

			if(!(tmp_path = strstr(tmp_path, "files")))
				goto drop_path;

			tmp_path = tmp_path + 5;

			memcpy(cPath, tmp_path, strlen(tmp_path));
			success = 1;
			printk("[%s] cPath@%s buf@%s\n", __func__, cPath, buf);

drop_path:
			if(path_buf)
				kfree(path_buf);
			if(fuse_dentry)
				dput(fuse_dentry);
		
			if(!success)
			{
				dput(xfs_dentry);
				kfree(buf);
				goto close_d_normal;
			}
			
		}

		for (sleep_count = 0; sleep_count < 5; sleep_count++)
		{
			if (S_ISDIR(xfs_dentry->d_inode->i_mode))
				xfs_filp = filp_open(buf, O_DIRECTORY, 0);
			else
				xfs_filp = filp_open(buf, O_RDONLY, 0);
			if (IS_ERR(xfs_filp))
			{
				printk("[%s] path_translated@%s inodeID: %llu, gen: %u length, %d cPath: %s filp_open failed:%ld\n"
					, __func__, fc->mount_path_translated, handle->nodeid, handle->generation
					, length, buf, PTR_ERR(xfs_filp));
			}
			else
				break;
			msleep_interruptible(500);
		}
		dput(xfs_dentry);
		kfree(buf);
		if (sleep_count >= 5)
		{
			printk("[%s] retry 5 times still error\n", __func__);
			goto close_d_normal;
		}
		fput(xfs_filp);
		inode = ilookup5(sb, handle->nodeid, fuse_inode_eq, &handle->nodeid);

		if (!inode) {
			err = -ESTALE;
			goto err_clean_out;
		}
		err = -EIO;
		if (get_node_id(inode) != handle->nodeid)
			goto err_iput_out;

		fput(dfilp);
		entry = d_obtain_alias(inode);

		//printk("[%s] entry@%s ino@%lu gen@%u success\n", __func__, entry->d_iname, inode->i_ino, inode->i_generation);
		
		return entry;

err_iput_out:
		iput(inode);
err_clean_out:
		fput(dfilp);
		goto out_err;
dput_normal:
		dput(xfs_dentry);
close_d_normal:
		fput(dfilp);
	}

normal_lookup:

	name.len = 1;
	name.name = ".";
	err = fuse_lookup_name(sb, handle->nodeid, &name, &outarg,
			       &inode, NULL, NULL);
	if (err && err != -ENOENT)
		goto out_err;
	if (err || !inode) {
		err = -ESTALE;
		goto out_err;
	}
	err = -EIO;
	if (get_node_id(inode) != handle->nodeid)
		goto out_iput;

inode_found:
	err = -ESTALE;
	if (inode->i_generation != handle->generation)
		goto out_iput;

	entry = d_obtain_alias(inode);
	if (!IS_ERR(entry) && get_node_id(inode) != FUSE_ROOT_ID)
		fuse_invalidate_entry_cache(entry);

	return entry;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

static char* xfs_path_to_cache(char *path)
{
    char *nowptr = path;
    int i = 3;

    for(i = 3; i > 0; i--)
    {
        nowptr = strchr(nowptr, '/');
        if (!nowptr)
            return NULL;
        
        nowptr += 1;
    }
    return nowptr - 1;
}

void fuse_set_encode_info(struct dentry *entry, struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn_super(inode->i_sb);
	struct file *dfilp;
	struct dentry *xfs_dentry;
	char *buf = NULL, *path =NULL;

	if (fc->iscache && fc->mount_path)
	{
		struct dentry *fuse_dentry;
		struct file *cache_file = NULL;
		fuse_dentry = (entry != NULL)? entry: d_find_alias(inode);
		if(fuse_dentry)
		{
			char *real_path = NULL;
			int success = 0;
			path = fuse_prepare_path(fc, fuse_dentry, buf);
			if(!path)
				goto drop_path;
			
			real_path = path_translate(path);
			if(!real_path)
				goto drop_path;

			if (S_ISDIR(inode->i_mode))
				cache_file = filp_open(real_path, O_DIRECTORY, 0);
			else
				cache_file = filp_open(real_path, O_RDONLY, 0);

			if (IS_ERR(cache_file))
				goto free_cache_normal;

			path = path + strlen(fc->mount_path);

			cache_file->f_inode->i_op->setxattr(cache_file->f_dentry, "user.whoami", (void *) path, strlen(path), 0);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

			dput(fuse_dentry);

			if(success)
				return;
		}

		//printk("fuse_encode_fh fuse enter\n");

		if (!fc->mount_path_translated)
			fc->mount_path_translated = path_translate(fc->mount_path);

		dfilp = filp_open(fc->mount_path_translated, O_DIRECTORY, 0);
		if (IS_ERR(dfilp))
		{
			printk("[%s] path_translated@%s inodeID@%lu, gen@%u open translated failed: %ld\n"
				, __func__, fc->mount_path_translated, inode->i_ino, inode->i_generation, PTR_ERR(dfilp));
			return;
		}

		if (!dfilp->f_op->get_dentry)
			return;

		xfs_dentry = dfilp->f_op->get_dentry(dfilp, inode->i_ino, inode->i_generation);
		if (xfs_dentry == NULL)
		{
			printk("[%s] path_translated@%s inodeID@%lu, gen@%u get_dentry failed: NULL\n"
				, __func__, fc->mount_path_translated, inode->i_ino, inode->i_generation);
			goto fput_out;
		}
		if (IS_ERR(xfs_dentry))
		{
			printk("[%s] path_translated@%s inodeID@%lu, gen@%u get_dentry failed: %ld\n"
				, __func__, fc->mount_path_translated, inode->i_ino, inode->i_generation, PTR_ERR(xfs_dentry));
			goto fput_out;
		}

		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buf)
		{
			printk("[%s] path_translated@%s inodeID@%lu, gen@%u buf alloc failed\n"
				, __func__, fc->mount_path_translated, inode->i_ino, inode->i_generation);
			goto dput_out;;
		}
		memset(buf, 0 , PATH_MAX);
		path = dentry_path_raw(xfs_dentry, buf, PATH_MAX);
		path = xfs_path_to_cache(path);
		if (!path)
		{
			printk("[%s] path_translated@%s inodeID@%lu, gen@%u xfs_path_to_cache return NULL\n"
				, __func__, fc->mount_path_translated, inode->i_ino, inode->i_generation);
			goto free_out;
		}

		xfs_dentry->d_inode->i_op->setxattr(xfs_dentry, "user.whoami", (void *) path, strlen(path), 0);
		printk("[%s] test start222 path@%s success\n", __func__, path);
		
	
free_out:	
	kfree(buf);

dput_out:
	dput(xfs_dentry);

fput_out:
	fput(dfilp);
	}
}

static int fuse_encode_fh(struct inode *inode, u32 *fh, int *max_len,
			   struct inode *parent)
{	
	int len = parent ? 6 : 3;
	u64 nodeid;
	u32 generation;

	fuse_set_encode_info(NULL, inode);

	if (*max_len < len) {
		*max_len = len;
		return  FILEID_INVALID;
	}

	nodeid = get_fuse_inode(inode)->nodeid;
	generation = inode->i_generation;

	fh[0] = (u32)(nodeid >> 32);
	fh[1] = (u32)(nodeid & 0xffffffff);
	fh[2] = generation;

	if (parent) {
		nodeid = get_fuse_inode(parent)->nodeid;
		generation = parent->i_generation;

		fh[3] = (u32)(nodeid >> 32);
		fh[4] = (u32)(nodeid & 0xffffffff);
		fh[5] = generation;
	}

	*max_len = len;
	return parent ? 0x82 : 0x81;
}

/* get ro path */
static int get_sub_path(char* readbuf, int idx, struct list_head *bucket_sub_list){
	//char *sub_pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	int path_idx = 0;

	//INIT ro path
	shared_bucket_sub_t *sub_node = kmalloc(sizeof(shared_bucket_sub_t), GFP_KERNEL);
	char *sub_pathbuf = sub_node->sub_path;
	memset(sub_node, 0, sizeof(shared_bucket_sub_t));
	// INIT_LIST_HEAD(&sub_node->sub_list);
	list_add_tail(&sub_node->sub_list, bucket_sub_list);


	while(*(readbuf+idx) != ' ' &&  *(readbuf+idx) != '!'){
		if(*(readbuf+idx) == '?' || *(readbuf+idx) == '&')
			sub_node->permissions = (*(readbuf+idx) == '?')? 1:0;
		else
			*(sub_pathbuf+path_idx) = *(readbuf+idx);
		path_idx++;
		idx++;
	}
	*(sub_pathbuf+path_idx-2) = '\0'; // -1 would be '?'|'&', -2 to remove tail '/'.
	if(*(readbuf+idx) == ' ')
		idx++;
	// kfree(sub_pathbuf);
	return idx; //len of ro path
}

/* get rw path */
static int get_mnt_path(char* readbuf, int idx, struct list_head *listptr){
	int retval = 0, path_idx = 0;

	// INIT rw node
	shared_bucket_mnt_t *mnt_node = kmalloc(sizeof(shared_bucket_mnt_t), GFP_KERNEL);
	char *mnt_pathbuf = mnt_node->mnt_path;
	memset(mnt_node, 0, sizeof(shared_bucket_mnt_t));
	list_add_tail(&mnt_node->mnt_list, listptr);
	mnt_node->sub_list = kmalloc(sizeof(struct list_head), GFP_KERNEL);
	INIT_LIST_HEAD(mnt_node->sub_list);

	// fill path
	while(*(readbuf+idx) != '?' && *(readbuf+idx) != '&' && *(readbuf+idx) != '!'){
		*(mnt_pathbuf+path_idx) = *(readbuf+idx);
		path_idx++;
		idx++;
	}

	*(mnt_pathbuf+path_idx-1) = '\0'; // -1 to remove tail '/'.
	// kfree(mnt_pathbuf);

	// now we got rw path
	switch(*(readbuf+idx)){
		case '!':
			// we break, and get next bucket info
			return idx; //len of rw path
		case '?':
		case '&':
			mnt_node->permissions = (*(readbuf+idx) == '?')? 1: 0;
			if(*(readbuf+idx+1) == '!'){
				// we break, and get next bucket info
				idx++;      //shift to "!"
				return idx;
			}

			// get sub path of this bucket
			idx++;
			while(*(readbuf+idx) != '!'){
				retval = get_sub_path(readbuf, idx, mnt_node->sub_list);
				idx = retval;
			}
			return retval;
		default:
			// should not go here
			printk("[%s] should not go here, format wrong?\n", __func__);
			return idx; //len of rw path

	}
	return idx; //len of rw path
}

/* parser list table */
static void parser_table(char *readbuf, int table_len, struct list_head *listptr){
	int idx = 0, retval = 0;

	while(idx < table_len){
		switch(*(readbuf+idx)){
			case ';':
			    // get rw path
				idx++; // we do not need ';' in path.
				retval = get_mnt_path(readbuf, idx, listptr);
				idx = retval;
				break;
		}
		idx++;
		// prevent infinie loop
		if(idx > 64*PATH_MAX){
			printk("[%s] idx >  64*4k !\n", __func__);
			return;
		}
	}
	return;
}

/* load shared bucket list */
struct list_head *init_shared_list(char *mount_path){
	
	mm_segment_t old_fs = get_fs();
	char *xfs_mount_path = path_translate(mount_path);
	char *mount_table_path = kmalloc(PATH_MAX, GFP_KERNEL);
	char *readbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	char *table_name = "share_table";
	struct file *fp = NULL;
	int retval = 0, back_slash_cnt = 0, pathidx = 0;
	struct list_head *listptr = kmalloc(sizeof(struct list_head), GFP_KERNEL);

	if(!xfs_mount_path || !mount_table_path || !readbuf){
		printk("[%s] get xfs_mount_path fail\n", __func__);
		goto OPEN_FAIL;
	}
	if(listptr)
		INIT_LIST_HEAD(listptr);
	else{
		printk("[%s] get listptr fail\n", __func__);
		goto EXIT;
	}

	// remove "files" in translated path
	while(*(xfs_mount_path+pathidx) != '\0'){
		if(*(xfs_mount_path+pathidx) == '/')
			back_slash_cnt++;
		if(back_slash_cnt == 4){
			*(xfs_mount_path+pathidx+1) = '\0';
			break;
		}
		pathidx++;
	}
	// get table path
	memset(readbuf, 0, sizeof(PATH_MAX));
	strcpy(mount_table_path, xfs_mount_path);
	strcat(mount_table_path, table_name);
	kfree(xfs_mount_path);
    
	// INIT KERNEL ENV
    set_fs(KERNEL_DS);

	fp = filp_open(mount_table_path, O_RDONLY, 0);
	if(!fp || IS_ERR(fp)){
OPEN_FAIL:
		printk("[%s] open shared list fail!\n", __func__);
		if(listptr)
			kfree(listptr);
		listptr = NULL;
		goto EXIT;
	}
	else{
		if (fp->f_op && fp->f_op->read){
			// read from table
      		retval = fp->f_op->read(fp, readbuf, PATH_MAX*64, &fp->f_pos);
      		parser_table(readbuf, retval, listptr);
        }
        filp_close(fp, NULL);
	}
EXIT:
	if(mount_table_path)
		kfree(mount_table_path);
	if(readbuf)
		kfree(readbuf);
	//DINIT KERNEL ENV
	set_fs(old_fs);
	return listptr;
}

void free_shared_bucket_list(struct list_head *shared_bucket_list){
	shared_bucket_sub_t *sub_Pos;
	shared_bucket_mnt_t *mnt_Pos;

	list_for_each_entry(mnt_Pos, shared_bucket_list, mnt_list){
		// free sub list
		if(!list_empty(mnt_Pos->sub_list)){
			list_for_each_entry(sub_Pos, mnt_Pos->sub_list, sub_list){
				list_del(&(sub_Pos->sub_list));
			    kfree(sub_Pos);
			}
		}
		// free mnt node
		list_del(&(mnt_Pos->mnt_list));
		kfree(mnt_Pos);
	}
}

static struct dentry *fuse_fh_to_dentry(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct fuse_inode_handle handle;

	if ((fh_type != 0x81 && fh_type != 0x82) || fh_len < 3)
		return NULL;

	handle.nodeid = (u64) fid->raw[0] << 32;
	handle.nodeid |= (u64) fid->raw[1];
	handle.generation = fid->raw[2];
	return fuse_get_dentry(sb, &handle);
}

static struct dentry *fuse_fh_to_parent(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct fuse_inode_handle parent;

	if (fh_type != 0x82 || fh_len < 6)
		return NULL;

	parent.nodeid = (u64) fid->raw[3] << 32;
	parent.nodeid |= (u64) fid->raw[4];
	parent.generation = fid->raw[5];
	return fuse_get_dentry(sb, &parent);
}

static struct dentry *fuse_get_parent(struct dentry *child)
{
	struct inode *child_inode = child->d_inode;
	struct fuse_conn *fc = get_fuse_conn(child_inode);
	struct inode *inode;
	struct dentry *parent;
	struct fuse_entry_out outarg;
	struct qstr name;
	int err;

	if (!fc->export_support)
		return ERR_PTR(-ESTALE);

	name.len = 2;
	name.name = "..";
	printk("[%s] child@%s\n", __func__, child->d_iname);
	err = fuse_lookup_name(child_inode->i_sb, get_node_id(child_inode),
			       &name, &outarg, &inode, NULL, child);
	if (err) {
		if (err == -ENOENT)
			return ERR_PTR(-ESTALE);
		return ERR_PTR(err);
	}

	parent = d_obtain_alias(inode);
	if (!IS_ERR(parent) && get_node_id(inode) != FUSE_ROOT_ID)
		fuse_invalidate_entry_cache(parent);

	return parent;
}

static const struct export_operations fuse_export_operations = {
	.fh_to_dentry	= fuse_fh_to_dentry,
	.fh_to_parent	= fuse_fh_to_parent,
	.encode_fh	= fuse_encode_fh,
	.get_parent	= fuse_get_parent,
};

static const struct super_operations fuse_super_operations = {
	.alloc_inode    = fuse_alloc_inode,
	.destroy_inode  = fuse_destroy_inode,
	.evict_inode	= fuse_evict_inode,
	.drop_inode	= generic_delete_inode,
	.remount_fs	= fuse_remount_fs,
	.put_super	= fuse_put_super,
	.umount_begin	= fuse_umount_begin,
	.statfs		= fuse_statfs,
	.show_options	= fuse_show_options,
};

static void sanitize_global_limit(unsigned *limit)
{
	if (*limit == 0)
		*limit = ((num_physpages << PAGE_SHIFT) >> 13) /
			 sizeof(struct fuse_req);

	if (*limit >= 1 << 16)
		*limit = (1 << 16) - 1;
}

static int set_global_limit(const char *val, struct kernel_param *kp)
{
	int rv;

	rv = param_set_uint(val, kp);
	if (rv)
		return rv;

	sanitize_global_limit((unsigned *)kp->arg);

	return 0;
}

static void process_init_limits(struct fuse_conn *fc, struct fuse_init_out *arg)
{
	int cap_sys_admin = capable(CAP_SYS_ADMIN);

	if (arg->minor < 13)
		return;

	sanitize_global_limit(&max_user_bgreq);
	sanitize_global_limit(&max_user_congthresh);

	if (arg->max_background) {
		fc->max_background = arg->max_background;

		if (!cap_sys_admin && fc->max_background > max_user_bgreq)
			fc->max_background = max_user_bgreq;
	}
	if (arg->congestion_threshold) {
		fc->congestion_threshold = arg->congestion_threshold;

		if (!cap_sys_admin &&
		    fc->congestion_threshold > max_user_congthresh)
			fc->congestion_threshold = max_user_congthresh;
	}
}

static void process_init_reply(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_init_out *arg = &req->misc.init_out;

	if (req->out.h.error || arg->major != FUSE_KERNEL_VERSION)
		fc->conn_error = 1;
	else {
		unsigned long ra_pages;

		process_init_limits(fc, arg);

		if (arg->minor >= 6) {
			ra_pages = arg->max_readahead / PAGE_CACHE_SIZE;
			if (arg->flags & FUSE_ASYNC_READ)
				fc->async_read = 1;
			if (!(arg->flags & FUSE_POSIX_LOCKS))
				fc->no_lock = 1;
			if (arg->minor >= 17) {
				if (!(arg->flags & FUSE_FLOCK_LOCKS))
					fc->no_flock = 1;
			} else {
				if (!(arg->flags & FUSE_POSIX_LOCKS))
					fc->no_flock = 1;
			}
			if (arg->flags & FUSE_ATOMIC_O_TRUNC)
				fc->atomic_o_trunc = 1;
			if (arg->minor >= 9) {
				/* LOOKUP has dependency on proto version */
				if (arg->flags & FUSE_EXPORT_SUPPORT)
					fc->export_support = 1;
			}
			if (arg->flags & FUSE_BIG_WRITES)
				fc->big_writes = 1;
			if (arg->flags & FUSE_DONT_MASK)
				fc->dont_mask = 1;
			if (arg->flags & FUSE_AUTO_INVAL_DATA)
				fc->auto_inval_data = 1;
			if (arg->flags & FUSE_DO_READDIRPLUS) {
				fc->do_readdirplus = 1;
				if (arg->flags & FUSE_READDIRPLUS_AUTO)
					fc->readdirplus_auto = 1;
			}
			if (arg->flags & FUSE_ASYNC_DIO)
				fc->async_dio = 1;
		} else {
			ra_pages = fc->max_read / PAGE_CACHE_SIZE;
			fc->no_lock = 1;
			fc->no_flock = 1;
		}

		fc->bdi.ra_pages = min(fc->bdi.ra_pages, ra_pages);
		fc->minor = arg->minor;
		fc->max_write = arg->minor < 5 ? 4096 : arg->max_write;
		fc->max_write = max_t(unsigned, 4096, fc->max_write);
		fc->conn_init = 1;
	}
	fc->initialized = 1;
	wake_up_all(&fc->blocked_waitq);
}

static void fuse_send_init(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_init_in *arg = &req->misc.init_in;

	arg->major = FUSE_KERNEL_VERSION;
	arg->minor = FUSE_KERNEL_MINOR_VERSION;
	arg->max_readahead = fc->bdi.ra_pages * PAGE_CACHE_SIZE;
	arg->flags |= FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_ATOMIC_O_TRUNC |
		FUSE_EXPORT_SUPPORT | FUSE_BIG_WRITES | FUSE_DONT_MASK |
		FUSE_SPLICE_WRITE | FUSE_SPLICE_MOVE | FUSE_SPLICE_READ |
		FUSE_FLOCK_LOCKS | FUSE_HAS_IOCTL_DIR | FUSE_AUTO_INVAL_DATA |
		FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO | FUSE_ASYNC_DIO;
	req->in.h.opcode = FUSE_INIT;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*arg);
	req->in.args[0].value = arg;
	req->out.numargs = 1;
	/* Variable length argument used for backward compatibility
	   with interface version < 7.5.  Rest of init_out is zeroed
	   by do_get_request(), so a short reply is not a problem */
	req->out.argvar = 1;
	req->out.args[0].size = sizeof(struct fuse_init_out);
	req->out.args[0].value = &req->misc.init_out;
	req->end = process_init_reply;
	fuse_request_send_background(fc, req);
}

static void fuse_free_conn(struct fuse_conn *fc)
{
	kfree(fc);
}

static int fuse_bdi_init(struct fuse_conn *fc, struct super_block *sb)
{
	int err;

	fc->bdi.name = "fuse";
	fc->bdi.ra_pages = (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE;
	/* fuse does it's own writeback accounting */
	fc->bdi.capabilities = BDI_CAP_NO_ACCT_WB | BDI_CAP_STRICTLIMIT;

	err = bdi_init(&fc->bdi);
	if (err)
		return err;

	fc->bdi_initialized = 1;

	if (sb->s_bdev) {
		err =  bdi_register(&fc->bdi, NULL, "%u:%u-fuseblk",
				    MAJOR(fc->dev), MINOR(fc->dev));
	} else {
		err = bdi_register_dev(&fc->bdi, fc->dev);
	}

	if (err)
		return err;

	/*
	 * For a single fuse filesystem use max 1% of dirty +
	 * writeback threshold.
	 *
	 * This gives about 1M of write buffer for memory maps on a
	 * machine with 1G and 10% dirty_ratio, which should be more
	 * than enough.
	 *
	 * Privileged users can raise it by writing to
	 *
	 *    /sys/class/bdi/<bdi>/max_ratio
	 */
	bdi_set_max_ratio(&fc->bdi, 1);

	return 0;
}


void enqueue_dirty(struct fuse_conn *fc)
{
	int i;
	i = atomic_read(&(fc->isuse));
	if (i != 0)
		return;

	i = atomic_inc_return(&fc->isuse);
	if (i != 1)
	{
		atomic_dec(&(fc->isuse));
		return;
	}

	queue_work(fc->async_wq, &fc->async_work);
}

void flush_dirty(char *path, loff_t *start, loff_t *end, u32 f_flags, fmode_t f_mode, u32 dirty_count)
{
	struct file            *filp;
	mm_segment_t           oldfs;
	yas3fs_dirty_range_t   *dirty_range;
	int 				   ret = 0, i;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	if (!path)
		goto out_setfs;

	filp = filp_open(path, f_flags, f_mode);

	if (IS_ERR(filp))
		goto out_setfs;

	dirty_range = kmalloc(sizeof(yas3fs_dirty_range_t), GFP_USER);
	memset(dirty_range, 0, sizeof(yas3fs_dirty_range_t));

	if (!dirty_range)
		goto out_fput;

	for (i = 0; i < dirty_count; i++)
	{
		dirty_range->start[i] = (start[i] - 1) * YAS3FS_DIRTY_FRAG;
		dirty_range->end[i] = (end[i] * YAS3FS_DIRTY_FRAG) - 1;
	}
	dirty_range->dirty_count = dirty_count;

	ret = filp->f_op->unlocked_ioctl(filp, YAS3FS_IOC_SET_DIRTY_MULTI, (unsigned long) dirty_range);
	if (ret != 0)
		printk("[%s] unlocked_ioctl failed, err:%d, path:%s", __func__, ret, path);
	
	kfree(dirty_range);
out_fput:
	fput(filp);
out_setfs:
	set_fs(oldfs);
	return;

}

static int _try_merge_dirty(loff_t *old_start, loff_t *old_end, 
						    loff_t start, loff_t end)
{
	/**
    loff_t old_start = data->start;
    loff_t old_end = data->end;

    *  case 1: continuous write
    *          set end as new end
    *  case 2: continuous write in revresed order
    *          set start as new start
    *  case 3: start offset is inside old dirty range
               set end to the larger
    *  case 4: end offset is inside old dirty range
               set start to the lesser
    */

    if (*old_start == 0 && *old_end == 0)
    {
    	*old_start = start;
    	*old_end = end;
    	return 1;
    }
    else if (start == (*old_end + 1))
        *old_end = end;
    else if (end == (*old_start - 1))
        *old_start = start;
    else if (start >= *old_start && start <= *old_end)
        *old_end = end > *old_end ? end : *old_end;
    else if (end >= *old_start && end <= *old_end)
        *old_start = start > *old_start ? *old_start : start;
    else if (start <= *old_start && end >= *old_end)
    {
    	*old_start = start;
    	*old_end = end;
    }
    else if (start >= *old_start && end <= *old_end)
    {}
    else
    	return -1;

    return 0;

}

static int try_merge_dirty(struct dirty_record *data, loff_t start, loff_t end)
{
	int ret = 0;
	int i = 0;

	for (i = 0; i < YAS3FS_N_DIRTY; i++)
	{
		ret = _try_merge_dirty(&data->start[i], &data->end[i], start, end);
		if (ret == 0)
			break;
		else if(ret == 1)
		{
			data->dirty_count = i + 1;
			ret = 0;
			break;
		}
	}

	return ret;
}


static struct dirty_record *__dirty_record_search(struct rb_root *root, u64 ino)
{
	struct rb_node *node = root->rb_node;

	while(node)
	{
		struct dirty_record *data;
		data = container_of(node, struct dirty_record, dirty_tree_node);

		if(ino > data->ino)
			node = node->rb_right;
		else if (ino < data->ino)
			node = node->rb_left;
		else
			return data;
	}

	return NULL;
}

static int __dirty_record_insert(struct rb_root *root, struct dirty_record *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	u64 ino = data->ino;

	while(*new)
	{
		struct dirty_record *this;
		this = container_of(*new, struct dirty_record, dirty_tree_node);
		parent = *new;

		if (ino > this->ino)
		    new = &((*new)->rb_right);
		else if (ino < this->ino)
			new = &((*new)->rb_left);
		else
			return false;
	}

	 rb_link_node(&data->dirty_tree_node, parent, new);
	 rb_insert_color(&data->dirty_tree_node, root);

	 return true;
}

int update_dirty(struct inode *inode, char *path, loff_t start, loff_t end,
				  u32 f_flags, fmode_t f_mode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);

	struct rb_root *t_root;
	struct list_head *l_root;
	struct dirty_record *data, *newData = NULL;
	loff_t oldStart[YAS3FS_N_DIRTY] = {0}, oldEnd[YAS3FS_N_DIRTY] = {0};

	spinlock_t *s_lock = &(fc->s_lock);
	unsigned long spin_flag;
	u64 ino = get_fuse_inode(inode)->nodeid;
	int path_len = 0, i;

	if (!fc->support_partial_upload)
		return -1;

	newData = kmalloc(sizeof(struct dirty_record), GFP_KERNEL);
	if (newData)
		memset(newData, 0, sizeof(struct dirty_record));

	start = start/YAS3FS_DIRTY_FRAG + 1;
	end   = end/YAS3FS_DIRTY_FRAG + 1;
	spin_lock_irqsave(s_lock, spin_flag);

	t_root = fc->dirty_root.dirty_root;
	l_root = fc->dirty_root.dirty_list_nood;
	if ((data = __dirty_record_search(t_root, ino)) != NULL)
	{
		// try merge here
		if (try_merge_dirty(data, start, end) != 0)
		{
			for (i = 0; i < YAS3FS_N_DIRTY; i++)
			{
				oldStart[i] = data->start[i];
				oldEnd[i] = data->end[i];
			}
			memset(data->start, 0, YAS3FS_N_DIRTY * sizeof(loff_t) * 2);
			data->dirty_count = 1;
			data->start[0] = start;
			data->end[0] = end; 

			spin_unlock_irqrestore(s_lock, spin_flag);
			flush_dirty(path, oldStart, oldEnd, f_flags, f_mode, 10);
        }
        else
        {
        	spin_unlock_irqrestore(s_lock, spin_flag);
        }

        goto free_out;
	}
	else if (newData)
	{
		data = newData;
		path_len = strlen(path);
		strncpy (data->path, path, path_len);
		data->ino = ino;
		data->start[0] = start;
		data->end[0] = end;
		data->f_flags = f_flags;
		data->f_mode = f_mode;

		data->dirty_count = 1;

		__dirty_record_insert(t_root, data);
		list_add(&data->dirty_list_node, l_root);

		enqueue_dirty(fc);
		spin_unlock_irqrestore(s_lock, spin_flag);
	}
	else
	{
		spin_unlock_irqrestore(s_lock, spin_flag);
		oldStart[0] = start;
		oldEnd[0] = end;
		flush_dirty(path, oldStart, oldEnd, f_flags, f_mode, 1);
	}
	
	return 0;	

free_out:
	if(newData)
		kfree(newData);
	return 0;
}

void flush_work_list(struct work_struct *work)
{
	struct fuse_conn *fc = container_of(work, struct fuse_conn, async_work);
	struct list_head l_root;
	struct dirty_record *data;

	spinlock_t *s_lock = &(fc->s_lock);
	unsigned long spin_flag;

	spin_lock_irqsave(s_lock, spin_flag);

	list_replace(fc->dirty_root.dirty_list_nood, &l_root);
	fc->dirty_root.dirty_root->rb_node = NULL;
	INIT_LIST_HEAD(fc->dirty_root.dirty_list_nood);
	atomic_dec(&(fc->isuse));
	spin_unlock_irqrestore(s_lock, spin_flag);

	while (!list_empty(&l_root))
	{
		data = list_first_entry(&l_root, struct dirty_record, dirty_list_node);
		if (data)
		{
			list_del(&(data->dirty_list_node));
			flush_dirty(data->path, data->start, data->end, data->f_flags, data->f_mode, data->dirty_count);
			kfree(data);
		}
	}
	msleep_interruptible(1000);
}

static int fuse_fill_super(struct super_block *sb, void *data, int silent)
{
	struct fuse_conn *fc;
	struct inode *root;
	struct fuse_mount_data d;
	struct file *file;
	struct dentry *root_dentry;
	struct fuse_req *init_req;
	int err;
	int is_bdev = sb->s_bdev != NULL;
	// add myself
	//struct list_head *pos_rw, *pos_ro;
	//shared_bucket_mnt_t *mnt_node;
	//shared_bucket_sub_t *sub_node;

	err = -EINVAL;
	if (sb->s_flags & MS_MANDLOCK)
		goto err;

	sb->s_flags &= ~MS_NOSEC;

	if (!parse_fuse_opt((char *) data, &d, is_bdev))
		goto err;

	if (is_bdev) {
#ifdef CONFIG_BLOCK
		err = -EINVAL;
		if (!sb_set_blocksize(sb, d.blksize))
			goto err;
#endif
	} else {
		sb->s_blocksize = PAGE_CACHE_SIZE;
		sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	}
	sb->s_magic = FUSE_SUPER_MAGIC;
	sb->s_op = &fuse_super_operations;
	sb->s_xattr = fuse_xattr_handlers;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_export_op = &fuse_export_operations;

	file = fget(d.fd);
	err = -EINVAL;
	if (!file)
		goto err;

	if ((file->f_op != &fuse_dev_operations) ||
	    (file->f_cred->user_ns != &init_user_ns))
		goto err_fput;

	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	err = -ENOMEM;
	if (!fc)
		goto err_fput;

	fuse_conn_init(fc);

	fc->dev = sb->s_dev;
	fc->sb = sb;
	err = fuse_bdi_init(fc, sb);
	if (err)
		goto err_put_conn;

	sb->s_bdi = &fc->bdi;

	/* Handle umasking inside the fuse code */
	if (sb->s_flags & MS_POSIXACL)
		fc->dont_mask = 1;
	sb->s_flags |= MS_POSIXACL;

	fc->release = fuse_free_conn;
	fc->flags = d.flags;
	fc->user_id = d.user_id;
	fc->group_id = d.group_id;
	fc->max_read = max_t(unsigned, 4096, d.max_read);
	fc->iscache = d.iscache;
	fc->support_partial_upload = d.support_partial_upload;

	if (d.mount_path)
	{
		fc->mount_path = d.mount_path;
		if (d.support_partial_upload)
			printk("[%s] support partial upload\n", d.mount_path);
		else
			printk("[%s] not support partial upload\n", d.mount_path);
	}
	else
		fc->mount_path = NULL;

	fc->mount_path_translated = NULL;

	/* shared bucket list */
    if(d.iscache && d.mount_path){
    	fc->shared_bucket_list = init_shared_list(d.mount_path);
    	// print out rule table
    /*	if(!fc->shared_bucket_list || IS_ERR(fc->shared_bucket_list))
    		printk("[%s] shared_bucket_list get fail!\n", __func__);
    	else{
    		list_for_each(pos_rw, fc->shared_bucket_list){
    			mnt_node = list_entry(pos_rw, shared_bucket_mnt_t, mnt_list);
    			if(mnt_node && !IS_ERR(mnt_node)){
    				printk("[%s] table:mnt_path@%s\n", __func__, mnt_node->mnt_path);
    				if(!list_empty(mnt_node->sub_list)){
    					list_for_each(pos_ro, mnt_node->sub_list){
    					sub_node = list_entry(pos_ro, shared_bucket_sub_t, sub_list);
    					if(sub_node && !IS_ERR(sub_node))
    						printk("[%s] table:sub_path@%s\n", __func__, sub_node->sub_path);
    					}	
    				}
    			}
    		}
    	}
    */
    }
    else
    	fc->shared_bucket_list = NULL;

	/* Used by get_root_inode() */
	sb->s_fs_info = fc;

	err = -ENOMEM;
	/* Init workqueue required struce here*/
	fc->dirty_root.dirty_root = kmalloc(sizeof(struct rb_root), GFP_KERNEL);
	if (!fc->dirty_root.dirty_root)
		goto err_put_conn;
	fc->dirty_root.dirty_root->rb_node = NULL;

	fc->dirty_root.dirty_list_nood = kmalloc(sizeof(struct list_head), GFP_KERNEL);
	if (!fc->dirty_root.dirty_list_nood)
		goto err_put_conn;
	INIT_LIST_HEAD(fc->dirty_root.dirty_list_nood);

	spin_lock_init(&(fc->s_lock));

	fc->async_wq = create_workqueue("dirty_range_flusher");
	if (!fc->async_wq)
		goto err_put_conn;
	INIT_WORK(&fc->async_work, flush_work_list);

	atomic_set(&fc->isuse, 0);

	root = fuse_get_root_inode(sb, d.rootmode);
	root_dentry = d_make_root(root);
	if (!root_dentry)
		goto err_put_conn;
	/* only now - we want root dentry with NULL ->d_op */
	sb->s_d_op = &fuse_dentry_operations;

	init_req = fuse_request_alloc(0);
	if (!init_req)
		goto err_put_root;
	init_req->background = 1;

	if (is_bdev) {
		fc->destroy_req = fuse_request_alloc(0);
		if (!fc->destroy_req)
			goto err_free_init_req;
	}

	mutex_lock(&fuse_mutex);
	err = -EINVAL;
	if (file->private_data)
		goto err_unlock;

	err = fuse_ctl_add_conn(fc);
	if (err)
		goto err_unlock;

	list_add_tail(&fc->entry, &fuse_conn_list);
	sb->s_root = root_dentry;
	fc->connected = 1;
	file->private_data = fuse_conn_get(fc);
	mutex_unlock(&fuse_mutex);
	/*
	 * atomic_dec_and_test() in fput() provides the necessary
	 * memory barrier for file->private_data to be visible on all
	 * CPUs after this
	 */
	fput(file);

	fuse_send_init(fc, init_req);

	return 0;

 err_unlock:
	mutex_unlock(&fuse_mutex);
 err_free_init_req:
	fuse_request_free(init_req);
 err_put_root:
	dput(root_dentry);
 err_put_conn:
	fuse_bdi_destroy(fc);
	fuse_conn_put(fc);
 err_fput:
	fput(file);
 err:
	return err;
}

static struct dentry *fuse_mount(struct file_system_type *fs_type,
		       int flags, const char *dev_name,
		       void *raw_data)
{
	if(!strcmp(dev_name, "yas3fs")) {
		//printk("ivan dev_name cmp match!\n");
		strcat((char*)raw_data, ",");
		strcat((char*)raw_data, "iscache");
	}
	return mount_nodev(fs_type, flags, raw_data, fuse_fill_super);
}

static void fuse_kill_sb_anon(struct super_block *sb)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);

	if (fc) {
		down_write(&fc->killsb);
		fc->sb = NULL;
		up_write(&fc->killsb);
	}

	kill_anon_super(sb);
}

static struct file_system_type fuse_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuse",
	.fs_flags	= FS_HAS_SUBTYPE,
	.mount		= fuse_mount,
	.kill_sb	= fuse_kill_sb_anon,
};
MODULE_ALIAS_FS("fuse");

#ifdef CONFIG_BLOCK
static struct dentry *fuse_mount_blk(struct file_system_type *fs_type,
			   int flags, const char *dev_name,
			   void *raw_data)
{
	return mount_bdev(fs_type, flags, dev_name, raw_data, fuse_fill_super);
}

static void fuse_kill_sb_blk(struct super_block *sb)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);

	if (fc) {
		down_write(&fc->killsb);
		fc->sb = NULL;
		up_write(&fc->killsb);
	}

	kill_block_super(sb);
}

static struct file_system_type fuseblk_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuseblk",
	.mount		= fuse_mount_blk,
	.kill_sb	= fuse_kill_sb_blk,
	.fs_flags	= FS_REQUIRES_DEV | FS_HAS_SUBTYPE,
};
MODULE_ALIAS_FS("fuseblk");

static inline int register_fuseblk(void)
{
	return register_filesystem(&fuseblk_fs_type);
}

static inline void unregister_fuseblk(void)
{
	unregister_filesystem(&fuseblk_fs_type);
}
#else
static inline int register_fuseblk(void)
{
	return 0;
}

static inline void unregister_fuseblk(void)
{
}
#endif

static void fuse_inode_init_once(void *foo)
{
	struct inode *inode = foo;

	inode_init_once(inode);
}

static int __init fuse_fs_init(void)
{
	int err;

	fuse_inode_cachep = kmem_cache_create("fuse_inode",
					      sizeof(struct fuse_inode),
					      0, SLAB_HWCACHE_ALIGN,
					      fuse_inode_init_once);
	err = -ENOMEM;
	if (!fuse_inode_cachep)
		goto out;

	err = register_fuseblk();
	if (err)
		goto out2;

	err = register_filesystem(&fuse_fs_type);
	if (err)
		goto out3;

	return 0;

 out3:
	unregister_fuseblk();
 out2:
	kmem_cache_destroy(fuse_inode_cachep);
 out:
	return err;
}

static void fuse_fs_cleanup(void)
{
	unregister_filesystem(&fuse_fs_type);
	unregister_fuseblk();

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(fuse_inode_cachep);
}

static struct kobject *fuse_kobj;
static struct kobject *connections_kobj;

static int fuse_sysfs_init(void)
{
	int err;

	fuse_kobj = kobject_create_and_add("fuse", fs_kobj);
	if (!fuse_kobj) {
		err = -ENOMEM;
		goto out_err;
	}

	connections_kobj = kobject_create_and_add("connections", fuse_kobj);
	if (!connections_kobj) {
		err = -ENOMEM;
		goto out_fuse_unregister;
	}

	return 0;

 out_fuse_unregister:
	kobject_put(fuse_kobj);
 out_err:
	return err;
}

static void fuse_sysfs_cleanup(void)
{
	kobject_put(connections_kobj);
	kobject_put(fuse_kobj);
}

static int __init fuse_init(void)
{
	int res;

	printk(KERN_INFO "fuse init (API version %i.%i)\n",
	       FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);

	INIT_LIST_HEAD(&fuse_conn_list);
	res = fuse_fs_init();
	if (res)
		goto err;

	res = fuse_dev_init();
	if (res)
		goto err_fs_cleanup;

	res = fuse_sysfs_init();
	if (res)
		goto err_dev_cleanup;

	res = fuse_ctl_init();
	if (res)
		goto err_sysfs_cleanup;

	sanitize_global_limit(&max_user_bgreq);
	sanitize_global_limit(&max_user_congthresh);

	return 0;

 err_sysfs_cleanup:
	fuse_sysfs_cleanup();
 err_dev_cleanup:
	fuse_dev_cleanup();
 err_fs_cleanup:
	fuse_fs_cleanup();
 err:
	return res;
}

static void __exit fuse_exit(void)
{
	printk(KERN_DEBUG "fuse exit\n");

	fuse_ctl_cleanup();
	fuse_sysfs_cleanup();
	fuse_fs_cleanup();
	fuse_dev_cleanup();
}

module_init(fuse_init);
module_exit(fuse_exit);
