/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/posix_acl.h>

static bool fuse_use_readdirplus(struct inode *dir, struct file *filp)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_inode *fi = get_fuse_inode(dir);

	if (!fc->do_readdirplus)
		return false;
	if (!fc->readdirplus_auto)
		return true;
	if (test_and_clear_bit(FUSE_I_ADVISE_RDPLUS, &fi->state))
		return true;
	if (filp->f_pos == 0)
		return true;
	return false;
}

static void fuse_advise_use_readdirplus(struct inode *dir)
{
	struct fuse_inode *fi = get_fuse_inode(dir);

	set_bit(FUSE_I_ADVISE_RDPLUS, &fi->state);
}

#if BITS_PER_LONG >= 64
static inline void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
}

static inline u64 fuse_dentry_time(struct dentry *entry)
{
	return entry->d_time;
}
#else
/*
 * On 32 bit archs store the high 32 bits of time in d_fsdata
 */
static void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
	entry->d_fsdata = (void *) (unsigned long) (time >> 32);
}

static u64 fuse_dentry_time(struct dentry *entry)
{
	return (u64) entry->d_time +
		((u64) (unsigned long) entry->d_fsdata << 32);
}
#endif

/*
 * FUSE caches dentries and attributes with separate timeout.  The
 * time in jiffies until the dentry/attributes are valid is stored in
 * dentry->d_time and fuse_inode->i_time respectively.
 */

/*
 * Calculate the time in jiffies until a dentry/attributes are valid
 */
static u64 time_to_jiffies(unsigned long sec, unsigned long nsec)
{
	if (sec || nsec) {
		struct timespec ts = {sec, nsec};
		return get_jiffies_64() + timespec_to_jiffies(&ts);
	} else
		return 0;
}

/*
 * Set dentry and possibly attribute timeouts from the lookup/mk*
 * replies
 */
static void fuse_change_entry_timeout(struct dentry *entry,
				      struct fuse_entry_out *o)
{
	fuse_dentry_settime(entry,
		time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

static u64 attr_timeout(struct fuse_attr_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static u64 entry_attr_timeout(struct fuse_entry_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

/*
 * Mark the attributes as stale, so that at the next call to
 * ->getattr() they will be fetched from userspace
 */
void fuse_invalidate_attr(struct inode *inode)
{
	get_fuse_inode(inode)->i_time = 0;
}

/*
 * Just mark the entry as stale, so that a next attempt to look it up
 * will result in a new lookup call to userspace
 *
 * This is called when a dentry is about to become negative and the
 * timeout is unknown (unlink, rmdir, rename and in some cases
 * lookup)
 */
void fuse_invalidate_entry_cache(struct dentry *entry)
{
	fuse_dentry_settime(entry, 0);
}

/*
 * Same as fuse_invalidate_entry_cache(), but also try to remove the
 * dentry from the hash
 */
static void fuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	fuse_invalidate_entry_cache(entry);
}

static void fuse_lookup_init(struct fuse_conn *fc, struct fuse_req *req,
			     u64 nodeid, struct qstr *name,
			     struct fuse_entry_out *outarg)
{
	memset(outarg, 0, sizeof(struct fuse_entry_out));
	req->in.h.opcode = FUSE_LOOKUP;
	req->in.h.nodeid = nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = name->len + 1;
	req->in.args[0].value = name->name;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(struct fuse_entry_out);
	req->out.args[0].value = outarg;
}

u64 fuse_get_attr_version(struct fuse_conn *fc)
{
	u64 curr_version;

	/*
	 * The spin lock isn't actually needed on 64bit archs, but we
	 * don't yet care too much about such optimizations.
	 */
	spin_lock(&fc->lock);
	curr_version = fc->attr_version;
	spin_unlock(&fc->lock);

	return curr_version;
}

/*
 * Check whether the dentry is still valid
 *
 * If the entry validity timeout has expired and the dentry is
 * positive, try to redo the lookup.  If the lookup results in a
 * different inode, then let the VFS invalidate the dentry and redo
 * the lookup once more.  If the lookup results in the same inode,
 * then refresh the attributes, timeouts and mark the dentry valid.
 */
static int fuse_dentry_revalidate(struct dentry *entry, unsigned int flags)
{
	struct inode *inode;
	struct dentry *parent;
	struct fuse_conn *fc;
	int ret;

	inode = ACCESS_ONCE(entry->d_inode);
	if (inode && is_bad_inode(inode))
		goto invalid;
	else if (time_before64(fuse_dentry_time(entry), get_jiffies_64()) ||
		 (flags & LOOKUP_REVAL)) {
		int err;
		struct fuse_entry_out outarg;
		struct fuse_req *req;
		struct fuse_forget_link *forget;
		u64 attr_version;

		/* For negative dentries, always do a fresh lookup */
		if (!inode)
			goto invalid;

		ret = -ECHILD;
		if (flags & LOOKUP_RCU)
			goto out;

		fc = get_fuse_conn(inode);
		req = fuse_get_req_nopages(fc);
		ret = PTR_ERR(req);
		if (IS_ERR(req))
			goto out;

		forget = fuse_alloc_forget();
		if (!forget) {
			fuse_put_request(fc, req);
			ret = -ENOMEM;
			goto out;
		}

		attr_version = fuse_get_attr_version(fc);

		parent = dget_parent(entry);
		fuse_lookup_init(fc, req, get_node_id(parent->d_inode),
				 &entry->d_name, &outarg);
		fuse_request_send(fc, req);
		dput(parent);
		err = req->out.h.error;
		fuse_put_request(fc, req);
		/* Zero nodeid is same as -ENOENT */
		if (!err && !outarg.nodeid)
			err = -ENOENT;
		if (!err) {
			struct fuse_inode *fi = get_fuse_inode(inode);
			if (outarg.nodeid != get_node_id(inode)) {
				fuse_queue_forget(fc, forget, outarg.nodeid, 1);
				goto invalid;
			}
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);
		}
		kfree(forget);
		if (err || (outarg.attr.mode ^ inode->i_mode) & S_IFMT)
			goto invalid;
		
		if(outarg.attr.size == 0 && inode->i_ino != 0)
			outarg.attr.size = inode->i_size;

		fuse_change_attributes(inode, &outarg.attr,
				       entry_attr_timeout(&outarg),
				       attr_version);
		fuse_change_entry_timeout(entry, &outarg);
	} else if (inode) {
		fc = get_fuse_conn(inode);
		if (fc->readdirplus_auto) {
			parent = dget_parent(entry);
			fuse_advise_use_readdirplus(parent->d_inode);
			dput(parent);
		}
	}
	ret = 1;
out:
	return ret;

invalid:
	ret = 0;
	if (check_submounts_and_drop(entry) != 0)
		ret = 1;
	goto out;
}

static int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == FUSE_ROOT_ID;
}

const struct dentry_operations fuse_dentry_operations = {
	.d_revalidate	= fuse_dentry_revalidate,
};

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}
void _fuse_copy_attr_to_arg(struct file *file, struct fuse_attr *attr)
{
	if(!IS_ERR(file))
	{
		attr->ino = file->f_inode->i_ino;
		attr->size = i_size_read(file->f_inode);
		attr->blocks = file->f_inode->i_blocks;
		attr->atime = file->f_inode->i_atime.tv_sec;
		attr->mtime = file->f_inode->i_mtime.tv_sec;
		attr->ctime = file->f_inode->i_ctime.tv_sec;
		attr->atimensec = file->f_inode->i_atime.tv_nsec;
		attr->mtimensec = file->f_inode->i_mtime.tv_nsec;
		attr->ctimensec = file->f_inode->i_ctime.tv_nsec;
		attr->mode = file->f_inode->i_mode;
		attr->nlink = file->f_inode->i_nlink;
		attr->uid = file->f_inode->i_uid.val;
		attr->gid = file->f_inode->i_gid.val;
		attr->rdev = file->f_inode->i_rdev;
		attr->blksize = (1 << file->f_inode->i_blkbits);
		attr->padding = 0;
	}
}
void fuse_copy_attr_to_arg(struct file *file, struct fuse_entry_out *arg)
{
	if(!IS_ERR(file))
	{
		arg->nodeid = file->f_inode->i_ino;
		arg->generation = file->f_inode->i_generation;
		
		_fuse_copy_attr_to_arg(file, &arg->attr);
	}
}

int fuse_lookup_by_local_fs(struct inode *parent, struct dentry *entry, struct fuse_entry_out *outarg)
{
	struct file *cache_file = NULL;
	char *path, *full_path = NULL, *real_path;
	
	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path)
		return -EIO;

	memset(path, 0, PATH_MAX);

	translate_path_from_dentry(parent, entry, path);

	printk("[%s] path@%s len@%ld\n", __func__, path, strlen(path));

	full_path= path + (PATH_MAX - strlen(path) - 1);

	memcpy(full_path, path, (strlen(path) + 1));

	memset(path, 0, (strlen(path) + 1));

	printk("[%s] fullpath@%s len@%ld\n", __func__, full_path, strlen(full_path));

	if (!full_path)
		goto free_path_normal;

	real_path = path_translate(full_path);
	if (!real_path)
		goto free_path_normal;

	printk("[%s] real_path@%s len@%ld\n", __func__, real_path, strlen(real_path));

	cache_file = filp_open(real_path, O_RDONLY | O_LARGEFILE, 0);
	if(IS_ERR(cache_file))
	{
		printk("[%s] ferr111@%ld\n", __func__, PTR_ERR(cache_file));
		cache_file = filp_open(real_path, O_DIRECTORY, 0);
	}
	
	if (IS_ERR(cache_file))
	{
		printk("[%s] ferr222@%ld\n", __func__, PTR_ERR(cache_file));
		goto free_cache_normal;
	}

	fuse_copy_attr_to_arg(cache_file, outarg);	

	printk("[%s] real_path1@%s full_path@%s name@%s nodeid@%llu generation@%llu\n"
		, __func__, real_path, full_path, entry->d_name.name, outarg->nodeid, outarg->generation);

	fput(cache_file);

free_cache_normal:
	kfree(real_path);
free_path_normal:
	kfree(path);

	return 0;

}

char *fuse_prepare_path(struct fuse_conn *fc, struct dentry *entry, char *buf)
{
	char *path;
	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if(!buf)
	{
		printk("[%s] has no memory to alloc buf\n", __func__);
		goto fail_alloc;
	}

	memset(buf, 0 , PATH_MAX);
	path = dentry_path_raw(entry, buf, PATH_MAX);
	if (IS_ERR(path))
	{
		printk("[%s] path has a err: %ld\n", __func__, PTR_ERR(path));
		goto fail_prepare_path;
	}

	path = path - strlen(fc->mount_path);
	memcpy(path, fc->mount_path, strlen(fc->mount_path));
	return path;
	
fail_prepare_path:
	kfree(buf);
fail_alloc:
	return NULL;
}

int travels_cache_path(struct fuse_conn *fc, char *real_path, struct fuse_entry_out *outarg)
{
	struct file *cache_file = NULL;
	char *nowptr = real_path;
	char *travels_path = kmalloc(strlen(real_path) + 1, GFP_KERNEL);
	int err = 0, i = 0;

	if (!travels_path)
		return -1;

	memset(travels_path, 0, strlen(real_path) + 1);

	for(i=0; i<4; i++) {
		nowptr = strchr(nowptr, '/');
		if (!nowptr)
		{
			err = -1;
			goto free_exit;
		}
		nowptr++;
	}

	while(nowptr)
	{
		//printk("[%s] nowptr@%s real@%s\n", __func__, nowptr, real_path);
		memcpy(travels_path, real_path, (nowptr - real_path + 1 - 2));
		nowptr = strchr(nowptr, '/');
		if(nowptr)
		{
			nowptr++;
			//printk("[%s] nowptr+1@%s len@%lu real@%s\n", __func__, nowptr, (nowptr - real_path + 1), real_path);
		}
		else
		{
			//printk("[%s] nowptr@%s len@%lu real@%s\n", __func__, nowptr, (nowptr - real_path + 1), real_path);
		}
		
		cache_file = filp_open(travels_path, O_DIRECTORY, 0);
		if (IS_ERR(cache_file))
		{
			printk("[%s] travels_path@%s real@%s open failed\n", __func__, travels_path, real_path);
			err = -1;
			goto free_exit;
		}
		else
		{
			//printk("[%s] travels_path@%s real@%s\n", __func__, travels_path, real_path);
		}

		if(!nowptr && outarg)
		{
			fuse_copy_attr_to_arg(cache_file, outarg);
			//printk("[%s] id@%llu gen@%llu\n", __func__, outarg->nodeid, outarg->generation);

		}

		fput(cache_file);
	}

free_exit:
	kfree(travels_path);
	return err;
	/*
	cache_file = filp_open(real_path, O_RDONLY | O_LARGEFILE, 0);
	if(IS_ERR(cache_file))
	{
		printk("[%s] ferr111@%ld\n", __func__, PTR_ERR(cache_file));
		cache_file = filp_open(real_path, O_DIRECTORY, 0);
	}
	*/
}

int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode, struct inode *parent, struct dentry *entry)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct fuse_req *req;
	struct fuse_forget_link *forget;
	u64 attr_version;
	int err;

	*inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > FUSE_NAME_MAX)
		goto out;

	req = fuse_get_req_nopages(fc);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out;

	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget) {
		fuse_put_request(fc, req);
		goto out;
	}

	attr_version = fuse_get_attr_version(fc);

	fuse_lookup_init(fc, req, nodeid, name, outarg);

	/*
	if(entry && parent)
	{
		req->out.h.error = fuse_lookup_by_local_fs(parent, entry, outarg);
	}
	else */if(entry)//parent == NULL && entry
	{
		char *buf = NULL, *path = NULL;
		char *real_path = NULL;
		int err = 0;
		if(parent == NULL)
			printk("[%s] test start111 for \n", __func__);

		path = fuse_prepare_path(fc, entry, buf);
		if(!path)
			goto drop_path;
		
		real_path = path_translate(path);
		if(!real_path)
			goto drop_path;

		if(parent == NULL)
			printk("[%s] test start111 realpath@%s\n", __func__, real_path);

		err = travels_cache_path(fc, real_path, outarg);

		kfree(real_path);
drop_path:
		if(buf)
			kfree(buf);
	}

//	else
	{
		fuse_request_send(fc, req);	
	}

	err = req->out.h.error;
	fuse_put_request(fc, req);
	/* Zero nodeid is same as -ENOENT, but with valid timeout */
	if (err || !outarg->nodeid)
		goto out_put_forget;

	err = -EIO;
	if (!outarg->nodeid)
		goto out_put_forget;
	if (!fuse_valid_type(outarg->attr.mode))
		goto out_put_forget;

	*inode = fuse_iget(sb, outarg->nodeid, outarg->generation,
			   &outarg->attr, entry_attr_timeout(outarg),
			   attr_version);
	/*
	if(entry && parent)
	{
		struct fuse_inode *fi= get_fuse_inode(*inode);
		spin_lock(&fc->lock);
		fi->nlookup--;
		spin_unlock(&fc->lock);

		printk("[%s] id@%llu find@%d nlookup@%lld\n", __func__, outarg->nodeid, (*inode)?1:0, fi->nlookup);
	}
	*/
	err = -ENOMEM;
	if (!*inode) {
		if(entry && parent)
		{
			//printk("[%s] id1@%llu find@%d\n", __func__, outarg->nodeid, (*inode)?1:0);
		}
		fuse_queue_forget(fc, forget, outarg->nodeid, 1);
		goto out;
	}
	err = 0;

 out_put_forget:
	kfree(forget);
 out:
 	if(entry && parent)
	{
		//printk("[%s] id2@%llu find@%d err@%d\n", __func__, outarg->nodeid, (*inode)?1:0, err);
	}
	return err;
}

static struct dentry *fuse_materialise_dentry(struct dentry *dentry,
					      struct inode *inode)
{
	struct dentry *newent;

	if (inode && S_ISDIR(inode->i_mode)) {
		struct fuse_conn *fc = get_fuse_conn(inode);

		mutex_lock(&fc->inst_mutex);
		newent = d_materialise_unique(dentry, inode);
		mutex_unlock(&fc->inst_mutex);
	} else {
		newent = d_materialise_unique(dentry, inode);
	}

	return newent;
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct fuse_entry_out outarg;
	struct inode *inode;
	struct dentry *newent;
	bool outarg_valid = true;

	err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode, dir, entry);
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	newent = fuse_materialise_dentry(entry, inode);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;
	if (outarg_valid)
		fuse_change_entry_timeout(entry, &outarg);
	else
		fuse_invalidate_entry_cache(entry);

	fuse_advise_use_readdirplus(dir);
	if(entry && dir)
	{
		//printk("[%s] id*@%llu outarg_valid@%d\n", __func__, outarg.nodeid, outarg_valid);
	}
	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

/*
 * Atomic create+open operation
 *
 * If the filesystem doesn't support this, then fall back to separate
 * 'mknod' + 'open' requests.
 */
static int fuse_create_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct inode *inode;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req;
	struct fuse_forget_link *forget;
	struct fuse_create_in inarg;
	struct fuse_open_out outopen;
	struct fuse_entry_out outentry;
	struct fuse_file *ff;
	struct posix_acl *default_acl = fuse_get_acl(dir, ACL_TYPE_DEFAULT);
	int success = 0;

	/* Userspace expects S_IFREG in create mode */
	BUG_ON((mode & S_IFMT) != S_IFREG);
	
	err = IS_ERR(default_acl) ? PTR_ERR(default_acl):0;
	if (err)
		goto out_err;

	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out_acl_release;

	req = fuse_get_req_nopages(fc);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out_put_forget_req;

	err = -ENOMEM;
	ff = fuse_file_alloc(fc);
	if (!ff)
		goto out_put_request;

	if (!fc->dont_mask)
		mode &= ~current_umask();

	flags &= ~O_NOCTTY;
	memset(&inarg, 0, sizeof(inarg));
	memset(&outentry, 0, sizeof(outentry));
	inarg.flags = flags;
	inarg.mode = mode;
	inarg.umask = current_umask();
	req->in.h.opcode = FUSE_CREATE;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 2;
	req->in.args[0].size = fc->minor < 12 ? sizeof(struct fuse_open_in) :
						sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	req->out.numargs = 2;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outentry);
	req->out.args[0].value = &outentry;
	req->out.args[1].size = sizeof(outopen);
	req->out.args[1].value = &outopen;

	
	if (fc->iscache && fc->mount_path)
	{
		struct file *cache_file = NULL;
		char *real_path = NULL;
		char *buf = NULL, *path = NULL;
	
		path = fuse_prepare_path(fc, entry, buf);
		if(!path)
			goto drop_path;
			
		real_path = path_translate(path);
		if(!real_path)
			goto drop_path;

		cache_file = filp_open(real_path, flags, mode);
		if (IS_ERR(cache_file))
			goto free_cache_normal;

		fuse_copy_attr_to_arg(cache_file, &outentry);

		outopen.fh = 0;
		outopen.open_flags = 1;

		fput(cache_file);

		success = 1;

free_cache_normal:
		kfree(real_path);
drop_path:
		if(buf)
			kfree(buf);
	}
	
	if(!success)
	{
		fuse_request_send(fc, req);
		err = req->out.h.error;
	}
	else
		err = 0;
	
	if (err)
		goto out_free_ff;

	err = -EIO;
	if (!S_ISREG(outentry.attr.mode) || invalid_nodeid(outentry.nodeid))
		goto out_free_ff;

	fuse_put_request(fc, req);
	printk("[%s] fh@%llu flags@%u =@%u\n", __func__, outopen.fh, outopen.open_flags, flags);
	ff->fh = outopen.fh;
	ff->nodeid = outentry.nodeid;
	ff->open_flags = outopen.open_flags;
	inode = fuse_iget(dir->i_sb, outentry.nodeid, outentry.generation,
			  &outentry.attr, entry_attr_timeout(&outentry), 0);
	printk("[%s] fh@%llu flags@%llu\n", __func__, ff->nodeid, outentry.generation);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		fuse_sync_release(ff, flags);
		fuse_queue_forget(fc, forget, outentry.nodeid, 1);
		err = -ENOMEM;
		goto out_acl_release;
	}
	kfree(forget);
	printk("[%s] fh@%llu flags@%llu end111\n", __func__, ff->nodeid, outentry.generation);
	err = fuse_inherit_acl(entry, inode, default_acl);
	if (unlikely(err)) {
		iput(inode);
		goto out_err;
	}
	printk("[%s] fh@%llu flags@%llu end111.5\n", __func__, ff->nodeid, outentry.generation);
	d_instantiate(entry, inode);
	fuse_change_entry_timeout(entry, &outentry);
	fuse_invalidate_attr(dir);
	printk("[%s] fh@%llu flags@%llu end111.6\n", __func__, ff->nodeid, outentry.generation);
	err = finish_open(file, entry, generic_file_open, opened);
	printk("[%s] fh@%llu flags@%llu end222@%d\n", __func__, ff->nodeid, outentry.generation ,err);
	if (err) {
		fuse_sync_release(ff, flags);
	} else {
		file->private_data = fuse_file_get(ff);
		fuse_finish_open(inode, file);
	}
	printk("[%s] fh@%llu flags@%llu end222.5@%d\n", __func__, ff->nodeid, outentry.generation ,err);
	return err;

out_free_ff:
	fuse_file_free(ff);
out_put_request:
	fuse_put_request(fc, req);
out_put_forget_req:
	kfree(forget);
out_acl_release:
	posix_acl_release(default_acl);
out_err:
	return err;
}

static int fuse_mknod(struct inode *, struct dentry *, umode_t, dev_t);
static int fuse_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct dentry *res = NULL;
	//
	char *full_path;
	int checklist;
	if(check_iscache(dir)){

        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
		translate_path_from_dentry(dir, entry, full_path);
		checklist = check_ACM_share_list_with_path(dir, full_path);
		if((checklist == 0 && (flags & 0x01)) || checklist == -1){
			kfree(full_path);
			return -EACCES;
		}
		kfree(full_path);
	}
	//
	if (d_unhashed(entry)) {
		res = fuse_lookup(dir, entry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			entry = res;
	}

	if (!(flags & O_CREAT) || entry->d_inode)
		goto no_open;

	/* Only creates */
	*opened |= FILE_CREATED;

	if (fc->no_create)
		goto mknod;

	err = fuse_create_open(dir, entry, file, flags, mode, opened);
	if (err == -ENOSYS) {
		fc->no_create = 1;
		goto mknod;
	}
out_dput:
	dput(res);
	return err;

mknod:
	err = fuse_mknod(dir, entry, mode, 0);
	if (err)
		goto out_dput;
no_open:
	return finish_no_open(file, res);
}

/*
 * Code shared between mknod, mkdir, symlink and link
 */
static int create_new_entry(struct fuse_conn *fc, struct fuse_req *req,
			    struct inode *dir, struct dentry *entry,
			    umode_t mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	int err;
	struct fuse_forget_link *forget;
	struct posix_acl *default_acl = (req->in.h.opcode == FUSE_MKNOD || req->in.h.opcode == FUSE_MKDIR) ? \
						fuse_get_acl(dir, ACL_TYPE_DEFAULT) : NULL;
	
	if (IS_ERR(default_acl)) {
		fuse_put_request(fc, req);
		return PTR_ERR(default_acl);
	}	
	forget = fuse_alloc_forget();
	if (!forget) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	memset(&outarg, 0, sizeof(outarg));
	req->in.h.nodeid = get_node_id(dir);
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, entry_attr_timeout(&outarg), 0);
	if (!inode) {
		fuse_queue_forget(fc, forget, outarg.nodeid, 1);
		posix_acl_release(default_acl);
		return -ENOMEM;
	}
	kfree(forget);
	err = fuse_inherit_acl(entry, inode, default_acl);
	if (unlikely(err)) {
		iput(inode);
		return err;
	}
	if (S_ISDIR(inode->i_mode)) {
		struct dentry *alias;
		mutex_lock(&fc->inst_mutex);
		alias = d_find_alias(inode);
		if (alias) {
			/* New directory must have moved since mkdir */
			mutex_unlock(&fc->inst_mutex);
			dput(alias);
			iput(inode);
			return -EBUSY;
		}
		d_instantiate(entry, inode);
		mutex_unlock(&fc->inst_mutex);
	} else
		d_instantiate(entry, inode);

	fuse_change_entry_timeout(entry, &outarg);
	fuse_invalidate_attr(dir);
	return 0;

 out_put_forget_req:
	kfree(forget);
	posix_acl_release(default_acl);
	return err;
}

static int fuse_mknod(struct inode *dir, struct dentry *entry, umode_t mode,
		      dev_t rdev)
{
	struct fuse_mknod_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	req->in.h.opcode = FUSE_MKNOD;
	req->in.numargs = 2;
	req->in.args[0].size = fc->minor < 12 ? FUSE_COMPAT_MKNOD_IN_SIZE :
						sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, mode);
}

static int fuse_create(struct inode *dir, struct dentry *entry, umode_t mode,
		       bool excl)
{
	return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_mkdir(struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_mkdir_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	char *full_path; 
	int checklist;

	if (IS_ERR(req))
		return PTR_ERR(req);

	if (!fc->dont_mask)
		mode &= ~current_umask();
	
	if(check_iscache(dir)){
        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
		translate_path_from_dentry(dir, entry, full_path);
		checklist = check_ACM_share_list_with_path(dir, full_path);
		if(checklist == 0 || checklist == -1){
			kfree(full_path);
			return -EACCES;
		}
		kfree(full_path);
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.umask = current_umask();
	req->in.h.opcode = FUSE_MKDIR;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, S_IFDIR);
}

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	unsigned len = strlen(link) + 1;
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);
	req->in.h.opcode = FUSE_SYMLINK;
	req->in.numargs = 2;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->in.args[1].size = len;
	req->in.args[1].value = link;
	return create_new_entry(fc, req, dir, entry, S_IFLNK);
}

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req;
	char *full_path;
	int checklist;

	if(check_iscache(dir)){
        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
		translate_path_from_dentry(dir, entry, full_path);
		checklist = check_ACM_share_list_with_path(dir, full_path);
		if(checklist == 0 || checklist == -1){
			kfree(full_path);
			return -EACCES;
		}
		kfree(full_path);
	}

	if (fc->iscache && entry->control_flags == 2)
	{
		err = 0;
		goto unkink_end;
	}

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.nodeid = get_node_id(dir);
	if(fc->iscache)
	{
		req->in.h.opcode = FUSE_SYNCDELETE;
		req->in.numargs = 2;
		req->in.args[0].size = entry->d_name.len + 1;
		req->in.args[0].value = entry->d_name.name;

		req->in.args[1].size = sizeof(unsigned int);
		req->in.args[1].value = &entry->control_flags;
	}
	else
	{
		req->in.h.opcode = FUSE_UNLINK;
		req->in.numargs = 1;
		req->in.args[0].size = entry->d_name.len + 1;
		req->in.args[0].value = entry->d_name.name;
	}
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
unkink_end:
	if (!err) {
		struct inode *inode = entry->d_inode;
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		/*
		 * If i_nlink == 0 then unlink doesn't make sense, yet this can
		 * happen if userspace filesystem is careless.  It would be
		 * difficult to enforce correct nlink usage so just ignore this
		 * condition here
		 */
		if (inode->i_nlink > 0)
			drop_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	char *full_path;
	int checklist;

	if (IS_ERR(req))
		return PTR_ERR(req);

	if(check_iscache(dir)){
        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
		translate_path_from_dentry(dir, entry, full_path);
		checklist = check_ACM_share_list_with_path(dir, full_path);
		if(checklist == 0 || checklist == -1){
			kfree(full_path);
			return -EACCES;
		}
		kfree(full_path);
	}

	req->in.h.nodeid = get_node_id(dir);

	if(fc->iscache)
	{
		req->in.h.opcode = FUSE_SYNCDRMDIR;
		req->in.numargs = 2;
		req->in.args[0].size = entry->d_name.len + 1;
		req->in.args[0].value = entry->d_name.name;
		req->in.args[1].size = sizeof(unsigned int);
        req->in.args[1].value = &entry->control_flags;
	}
	else
	{
		req->in.h.opcode = FUSE_RMDIR;
		req->in.numargs = 1;
		req->in.args[0].size = entry->d_name.len + 1;
		req->in.args[0].value = entry->d_name.name;
	}
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		clear_nlink(entry->d_inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}
int fuse_lower_rename(unsigned int flags, struct dentry *olddir
	, struct dentry *newdir, char *oldname, char *newname)
{
	struct dentry *odentry, *ndentry;
	struct dentry *trap = lock_rename(olddir, newdir);
	int err = 0;
	odentry = lookup_one_len(oldname, olddir, strlen(oldname));
	err = PTR_ERR(odentry);
	if (IS_ERR(odentry))
	{
		printk("[%s] err111@%d", __func__, err);
		goto out_err;
	}

	err = -ENOENT;
	if (!odentry->d_inode)
	{
		printk("[%s] err112@%d", __func__, err);
		goto out_dput_old;
	}
	err = -EINVAL;
	if (odentry == trap)
	{
		printk("[%s] err113@%d", __func__, err);
		goto out_dput_old;
	}

	ndentry = lookup_one_len(newname, newdir, strlen(newname));	
	err = PTR_ERR(ndentry);
	if (IS_ERR(ndentry))
	{
		printk("[%s] err114@%d", __func__, err);
		goto out_dput_old;
	}
	err = -ENOTEMPTY;
	if (ndentry == trap)
	{
		printk("[%s] err115@%d", __func__, err);
		goto out_dput_new;
	}

	err = vfs_rename(olddir->d_inode, odentry, newdir->d_inode, ndentry, NULL, flags);
	if(!err)
	{
		err = sync_inode_metadata(olddir->d_inode, 1);
		if(!err)
		{
			err = sync_inode_metadata(newdir->d_inode, 1);
			if(err)
				printk("[%s] err118@%d", __func__, err);
		}
		else
			printk("[%s] err117@%d", __func__, err);
	}
	else
		printk("[%s] err116@%d", __func__, err);

out_dput_new:
	dput(ndentry);
out_dput_old:
	dput(odentry);
out_err:
	unlock_rename(olddir, newdir);
	return err;
}

static int fuse_rename_common(struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent,
			      unsigned int flags, int opcode, size_t argsize)
{
	int err;
	struct fuse_rename2_in inarg;
	struct fuse_conn *fc = get_fuse_conn(olddir);
	struct fuse_req *req;
	char *full_path;
	int checklist;
	int success = 0;

	if(check_iscache(newdir)){
        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
		translate_path_from_dentry(newdir, newent, full_path);
		checklist = check_ACM_share_list_with_path(newdir, full_path);
		if(checklist == 0 || checklist == -1){
			kfree(full_path);
			return -EACCES;
		}
		kfree(full_path);
	}

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, argsize);
	inarg.newdir = get_node_id(newdir);
	inarg.flags = flags;
	req->in.h.opcode = opcode;
	req->in.h.nodeid = get_node_id(olddir);
	req->in.numargs = 3;
	req->in.args[0].size = argsize;
	req->in.args[0].value = &inarg;
	req->in.args[1].size = oldent->d_name.len + 1;
	req->in.args[1].value = oldent->d_name.name;
	req->in.args[2].size = newent->d_name.len + 1;
	req->in.args[2].value = newent->d_name.name;

	if (fc->iscache && fc->mount_path)
	{
		char *buf_olddir = NULL, *path_olddir =NULL;
		char *buf_newdir = NULL, *path_newdir =NULL;
		struct dentry *fuse_dentry_olddir = oldent->d_parent;
		struct dentry *fuse_dentry_newdir = newent->d_parent;
		struct file *cache_file_olddir = NULL;
		struct file *cache_file_newdir = NULL;
		char *real_path_olddir = NULL;
		char *real_path_newdir = NULL;

		
		if(oldent)
			printk("[%s] oldent@%s=%s ino@%lu gen@%u\n"
				, __func__, oldent->d_iname, oldent->d_name.name, oldent->d_inode->i_ino, oldent->d_inode->i_generation);
		
		if(newent)
		{
			printk("[%s] newent@%s=%s parent@%s\n"
				, __func__, newent->d_iname, newent->d_name.name, (newent->d_parent)? (char *)newent->d_parent->d_iname: (char *)"hekko");
			if(newent->d_inode)
				printk("[%s] newent@%s=%s ino@%lu gen@%u\n"
				, __func__, newent->d_iname, newent->d_name.name, newent->d_inode->i_ino, newent->d_inode->i_generation);
		}
		

		if(fuse_dentry_olddir)
		{
			path_olddir = fuse_prepare_path(fc, fuse_dentry_olddir, buf_olddir);
			if(!path_olddir)
				goto drop_path;

			printk("[%s] TESTT old@%s\n", __func__, path_olddir);
			
			real_path_olddir = path_translate(path_olddir);
			if(!real_path_olddir)
				goto drop_path;

			printk("[%s] TESTT old@%s real@%s\n", __func__, path_olddir, real_path_olddir);

			cache_file_olddir = filp_open(real_path_olddir, O_DIRECTORY, 0);

			if (IS_ERR(cache_file_olddir))
				goto free_cache_normal;
		}

		if(olddir != newdir && fuse_dentry_newdir)
		{
			path_newdir = fuse_prepare_path(fc, fuse_dentry_newdir, buf_newdir);
			if(!path_newdir)
				goto drop_path;
			
			printk("[%s] TESTT new@%s\n", __func__, path_newdir);

			real_path_newdir = path_translate(path_newdir);
			if(!real_path_newdir)
				goto drop_path;

			printk("[%s] TESTT new@%s real@%s\n", __func__, path_newdir, real_path_newdir);

			cache_file_newdir = filp_open(real_path_newdir, O_DIRECTORY, 0);

			if (IS_ERR(cache_file_newdir))
				goto free_cache_normal;
		}

		req->out.h.error = fuse_lower_rename(flags, cache_file_olddir->f_dentry
									, (cache_file_newdir)? cache_file_newdir->f_dentry: cache_file_olddir->f_dentry
									, oldent->d_iname, newent->d_iname);
	
		printk("[%s] TESTT oldent@%s=%s ino@%lu gen@%u err@%d\n"
				, __func__, oldent->d_iname, oldent->d_name.name
				, oldent->d_inode->i_ino, oldent->d_inode->i_generation
				, req->out.h.error);
			
free_cache_normal:
		if(real_path_olddir)
			kfree(real_path_olddir);
		if(real_path_newdir)
			kfree(real_path_newdir);
drop_path:
		if(buf_olddir)
			kfree(buf_olddir);
		if(buf_newdir)
			kfree(buf_newdir);

		if(cache_file_olddir && !IS_ERR(cache_file_olddir))
			fput(cache_file_olddir);
		if(cache_file_newdir && !IS_ERR(cache_file_newdir))
			fput(cache_file_newdir);
		
		if(!req->out.h.error)
			success = 1;

		//char *buf_oldent = NULL, *path_oldent =NULL;
		//struct file *cache_file_olddir = NULL;
		/*
		char *buf_olddir = NULL, *path_olddir =NULL;
		struct dentry *fuse_dentry_olddir;
		struct file *cache_file_olddir = NULL;
		fuse_dentry_olddir = d_find_alias(olddir);
		if(fuse_dentry_olddir)
		{
			char *real_path_olddir = NULL;
			path = fuse_prepare_path(fc, fuse_dentry_olddir, buf_olddir);
			if(!path)
				goto drop_path;
			
			real_path_olddir = path_translate(path_olddir);
			if(!real_path_olddir)
				goto drop_path;

			cache_file = filp_open(real_path, O_DIRECTORY, 0);

			if (S_ISDIR(olddir->i_mode))
				cache_file = filp_open(real_path, O_DIRECTORY, 0);
			else
				cache_file = filp_open(real_path, O_RDONLY, 0);

			if (IS_ERR(cache_file))
				goto free_cache_normal;

			if(opcode == FUSE_RENAME2)
				req->out.h.error = cache_file->f_inode->i_op->rename2(cache_file->f_path->mnt, cache_file->f_dentry, stat);
			else
				req->out.h.error = cache_file->f_inode->i_op->rename(cache_file->f_path->mnt, cache_file->f_dentry, stat);

			_fuse_copy_attr_to_arg(cache_file, &outarg.attr);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

			dput(fuse_dentry);
		}
		*/
	}

	if(!success)
	{
		fuse_request_send(fc, req);
	}
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		/* ctime changes */
		fuse_invalidate_attr(oldent->d_inode);

		if (flags & RENAME_EXCHANGE) {
			fuse_invalidate_attr(newent->d_inode);
		}

		fuse_invalidate_attr(olddir);
		if (olddir != newdir)
			fuse_invalidate_attr(newdir);

		/* newent will end up negative */
		if (!(flags & RENAME_EXCHANGE) && newent->d_inode) {
			fuse_invalidate_attr(newent->d_inode);
			fuse_invalidate_entry_cache(newent);
		}
		if (!(olddir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE)) 
		{
			fuse_set_encode_info(newent, oldent->d_inode);
		}
	} else if (err == -EINTR) {
		/* If request was interrupted, DEITY only knows if the
		   rename actually took place.  If the invalidation
		   fails (e.g. some process has CWD under the renamed
		   directory), then there can be inconsistency between
		   the dcache and the real filesystem.  Tough luck. */
		fuse_invalidate_entry(oldent);
		if (newent->d_inode)
			fuse_invalidate_entry(newent);
	}

	return err;
}

static int fuse_rename2(struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent,
			unsigned int flags)
{
	struct fuse_conn *fc = get_fuse_conn(olddir);
	int err;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EINVAL;

	if (flags) {
		if (fc->no_rename2 || fc->minor < 23)
			return -EINVAL;

		err = fuse_rename_common(olddir, oldent, newdir, newent, flags,
					 FUSE_RENAME2,
					 sizeof(struct fuse_rename2_in));
		if (err == -ENOSYS) {
			fc->no_rename2 = 1;
			err = -EINVAL;
		}
	} else {
		err = fuse_rename_common(olddir, oldent, newdir, newent, 0,
					 FUSE_RENAME,
					 sizeof(struct fuse_rename_in));
	}

	return err;
}

static int fuse_rename(struct inode *olddir, struct dentry *oldent,
		       struct inode *newdir, struct dentry *newent)
{
	return fuse_rename_common(olddir, oldent, newdir, newent, 0,
				  FUSE_RENAME,
				  sizeof(struct fuse_rename_in));
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);
	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	req->in.h.opcode = FUSE_LINK;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = newent->d_name.len + 1;
	req->in.args[1].value = newent->d_name.name;
	err = create_new_entry(fc, req, newdir, newent, inode->i_mode);
	/* Contrary to "normal" filesystems it can happen that link
	   makes two "logical" inodes point to the same "physical"
	   inode.  We invalidate the attributes of the old one, so it
	   will reflect changes in the backing inode (link count,
	   etc.)
	*/
	if (!err) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		inc_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
	} else if (err == -EINTR) {
		fuse_invalidate_attr(inode);
	}
	return err;
}

static void fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat)
{
	unsigned int blkbits;

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(&init_user_ns, attr->uid);
	stat->gid = make_kgid(&init_user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

static int fuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version;
	int success = 0;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	attr_version = fuse_get_attr_version(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (file && S_ISREG(inode->i_mode)) {
		struct fuse_file *ff = file->private_data;

		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	req->in.h.opcode = FUSE_GETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;

	if (fc->iscache && fc->mount_path)
	{
		char *buf = NULL, *path =NULL;
		struct dentry *fuse_dentry;
		struct file *cache_file = NULL;
		fuse_dentry = d_find_alias(inode);
		if(fuse_dentry)
		{
			char *real_path = NULL;
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

			//req->out.h.error = cache_file->f_inode->i_op->getattr(cache_file->f_path->mnt, cache_file->f_dentry, stat);

			_fuse_copy_attr_to_arg(cache_file, &outarg.attr);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

			dput(fuse_dentry);
		}
	}

	if(!success)
	{
		fuse_request_send(fc, req);
	}
		err = req->out.h.error;

	fuse_put_request(fc, req);
	if (!err) {
		if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
			make_bad_inode(inode);
			err = -EIO;
		} else {
			fuse_change_attributes(inode, &outarg.attr,
					       attr_timeout(&outarg),
					       attr_version);
			if (stat)
				fuse_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed, struct dentry *entry)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;
	bool r;

	/*
	if(entry && strstr(entry->d_iname, "www"))
		printk("[%s] file1@%s size@%llu inode@%lld @%ld\n"
			, __func__, entry->d_iname, entry->d_inode->i_size, inode->i_size, inode->i_ino);
	*/

	if (time_before64(fi->i_time, get_jiffies_64())) {
		r = true;
		err = fuse_do_getattr(inode, stat, file);
		/*
		if(entry && strstr(entry->d_iname, "www"))
		printk("[%s] file2@%s size@%llu inode@%lld @%ld\n"
			, __func__, entry->d_iname, entry->d_inode->i_size, inode->i_size, inode->i_ino);
		*/
	} else {
		r = false;
		err = 0;
		if (stat) {
			generic_fillattr(inode, stat);
			stat->mode = fi->orig_i_mode;
			stat->ino = fi->orig_ino;
		}
	}

	if (refreshed != NULL)
		*refreshed = r;

	return err;
}

int fuse_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name)
{
	int err = -ENOTDIR;
	struct inode *parent;
	struct dentry *dir;
	struct dentry *entry;

	parent = ilookup5(sb, parent_nodeid, fuse_inode_eq, &parent_nodeid);
	if (!parent)
		return -ENOENT;

	mutex_lock(&parent->i_mutex);
	if (!S_ISDIR(parent->i_mode))
		goto unlock;

	err = -ENOENT;
	dir = d_find_alias(parent);
	if (!dir)
		goto unlock;

	entry = d_lookup(dir, name);
	dput(dir);
	if (!entry)
		goto unlock;

	fuse_invalidate_attr(parent);
	fuse_invalidate_entry(entry);

	if (child_nodeid != 0 && entry->d_inode) {
		mutex_lock(&entry->d_inode->i_mutex);
		if (get_node_id(entry->d_inode) != child_nodeid) {
			err = -ENOENT;
			goto badentry;
		}
		if (d_mountpoint(entry)) {
			err = -EBUSY;
			goto badentry;
		}
		if (S_ISDIR(entry->d_inode->i_mode)) {
			shrink_dcache_parent(entry);
			if (!simple_empty(entry)) {
				err = -ENOTEMPTY;
				goto badentry;
			}
			entry->d_inode->i_flags |= S_DEAD;
		}
		dont_mount(entry);
		clear_nlink(entry->d_inode);
		err = 0;
 badentry:
		mutex_unlock(&entry->d_inode->i_mutex);
		if (!err)
			d_delete(entry);
	} else {
		err = 0;
	}
	dput(entry);

 unlock:
	mutex_unlock(&parent->i_mutex);
	iput(parent);
	return err;
}

/*
 * Calling into a user-controlled filesystem gives the filesystem
 * daemon ptrace-like capabilities over the current process.  This
 * means, that the filesystem daemon is able to record the exact
 * filesystem operations performed, and can also control the behavior
 * of the requester process in otherwise impossible ways.  For example
 * it can delay the operation for arbitrary length of time allowing
 * DoS against the requester.
 *
 * For this reason only those processes can call into the filesystem,
 * for which the owner of the mount has ptrace privilege.  This
 * excludes processes started by other users, suid or sgid processes.
 */
int fuse_allow_current_process(struct fuse_conn *fc)
{
	const struct cred *cred;

	if (fc->flags & FUSE_ALLOW_OTHER)
		return 1;

	cred = current_cred();
	if (uid_eq(cred->euid, fc->user_id) &&
	    uid_eq(cred->suid, fc->user_id) &&
	    uid_eq(cred->uid,  fc->user_id) &&
	    gid_eq(cred->egid, fc->group_id) &&
	    gid_eq(cred->sgid, fc->group_id) &&
	    gid_eq(cred->gid,  fc->group_id))
		return 1;

	return 0;
}

static int fuse_access(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_access_in inarg;
	int err;

	if (fc->no_access)
		return 0;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
	req->in.h.opcode = FUSE_ACCESS;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_access = 1;
		err = 0;
	}
	return err;
}

static int fuse_perm_getattr(struct inode *inode, int mask)
{
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	return fuse_do_getattr(inode, NULL, NULL);
}

/*
 * Check permission.  The two basic access models of FUSE are:
 *
 * 1) Local access checking ('default_permissions' mount option) based
 * on file mode.  This is the plain old disk filesystem permission
 * modell.
 *
 * 2) "Remote" access checking, where server is responsible for
 * checking permission in each inode operation.  An exception to this
 * is if ->permission() was invoked from sys_access() in which case an
 * access request is sent.  Execute permission is still checked
 * locally based on file mode.
 */
static int fuse_permission(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	bool refreshed = false;
	int err = 0;
	
	if (!fuse_allow_current_process(fc))
		return -EACCES;

	/*
	 * If attributes are needed, refresh them before proceeding
	 */
	if ((fc->flags & FUSE_DEFAULT_PERMISSIONS) ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		if (time_before64(fi->i_time, get_jiffies_64())) {
			refreshed = true;

			err = fuse_perm_getattr(inode, mask);
			if (err)
				return err;
		}
	}

	if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
		err = generic_permission(inode, mask);

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */
		if (err == -EACCES && !refreshed) {
			err = fuse_perm_getattr(inode, mask);
			if (!err)
				err = generic_permission(inode, mask);
		}

		/* Note: the opposite of the above test does not
		   exist.  So if permissions are revoked this won't be
		   noticed immediately, only after the attribute
		   timeout has expired */
	} else if (mask & (MAY_ACCESS | MAY_CHDIR)) {
		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;

		err = fuse_access(inode, mask);
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = fuse_perm_getattr(inode, mask);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 void *dstbuf, filldir_t filldir)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		int over;
		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		over = filldir(dstbuf, dirent->name, dirent->namelen,
			       file->f_pos, dirent->ino, dirent->type);
		if (over)
			break;

		buf += reclen;
		nbytes -= reclen;
		file->f_pos = dirent->off;
	}

	return 0;
}

static int fuse_direntplus_link(struct file *file,
				struct fuse_direntplus *direntplus,
				u64 attr_version)
{
	int err;
	struct fuse_entry_out *o = &direntplus->entry_out;
	struct fuse_dirent *dirent = &direntplus->dirent;
	struct dentry *parent = file->f_path.dentry;
	struct qstr name = QSTR_INIT(dirent->name, dirent->namelen);
	struct dentry *dentry;
	struct dentry *alias;
	struct inode *dir = parent->d_inode;
	struct fuse_conn *fc;
	struct inode *inode;

	if (!o->nodeid) {
		/*
		 * Unlike in the case of fuse_lookup, zero nodeid does not mean
		 * ENOENT. Instead, it only means the userspace filesystem did
		 * not want to return attributes/handle for this entry.
		 *
		 * So do nothing.
		 */
		return 0;
	}

	if (name.name[0] == '.') {
		/*
		 * We could potentially refresh the attributes of the directory
		 * and its parent?
		 */
		if (name.len == 1)
			return 0;
		if (name.name[1] == '.' && name.len == 2)
			return 0;
	}

	if (invalid_nodeid(o->nodeid))
		return -EIO;
	if (!fuse_valid_type(o->attr.mode))
		return -EIO;

	fc = get_fuse_conn(dir);

	name.hash = full_name_hash(name.name, name.len);
	dentry = d_lookup(parent, &name);
	if (dentry) {
		inode = dentry->d_inode;
		if (!inode) {
			d_drop(dentry);
		} else if (get_node_id(inode) != o->nodeid ||
			   ((o->attr.mode ^ inode->i_mode) & S_IFMT)) {
			err = d_invalidate(dentry);
			if (err)
				goto out;
		} else if (is_bad_inode(inode)) {
			err = -EIO;
			goto out;
		} else {
			struct fuse_inode *fi;
			fi = get_fuse_inode(inode);
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);

			fuse_change_attributes(inode, &o->attr,
					       entry_attr_timeout(o),
					       attr_version);

			/*
			 * The other branch to 'found' comes via fuse_iget()
			 * which bumps nlookup inside
			 */
			goto found;
		}
		dput(dentry);
	}

	dentry = d_alloc(parent, &name);
	err = -ENOMEM;
	if (!dentry)
		goto out;

	inode = fuse_iget(dir->i_sb, o->nodeid, o->generation,
			  &o->attr, entry_attr_timeout(o), attr_version);
	if (!inode)
		goto out;

	alias = fuse_materialise_dentry(dentry, inode);
	err = PTR_ERR(alias);
	if (IS_ERR(alias))
		goto out;

	if (alias) {
		dput(dentry);
		dentry = alias;
	}

found:
	fuse_change_entry_timeout(dentry, o);

	err = 0;
out:
	dput(dentry);
	return err;
}

static int parse_dirplusfile(char *buf, size_t nbytes, struct file *file,
			     void *dstbuf, filldir_t filldir, u64 attr_version)
{
	struct fuse_direntplus *direntplus;
	struct fuse_dirent *dirent;
	size_t reclen;
	int over = 0;
	int ret;

	while (nbytes >= FUSE_NAME_OFFSET_DIRENTPLUS) {
		direntplus = (struct fuse_direntplus *) buf;
		dirent = &direntplus->dirent;
		reclen = FUSE_DIRENTPLUS_SIZE(direntplus);

		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!over) {
			/* We fill entries into dstbuf only as much as
			   it can hold. But we still continue iterating
			   over remaining entries to link them. If not,
			   we need to send a FORGET for each of those
			   which we did not link.
			*/
			over = filldir(dstbuf, dirent->name, dirent->namelen,
				       file->f_pos, dirent->ino,
				       dirent->type);
			file->f_pos = dirent->off;
		}

		buf += reclen;
		nbytes -= reclen;

		ret = fuse_direntplus_link(file, direntplus, attr_version);
		if (ret)
			fuse_force_forget(file, direntplus->entry_out.nodeid);
	}

	return 0;
}

static int fuse_readdir(struct file *file, void *dstbuf, filldir_t filldir)
{
	int plus, err;
	size_t nbytes;
	struct page *page;
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version = 0;

	if (is_bad_inode(inode))
		return -EIO;

	req = fuse_get_req(fc, 1);
	if (IS_ERR(req))
		return PTR_ERR(req);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	plus = fuse_use_readdirplus(inode, file);
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = PAGE_SIZE;
	if (plus) {
		attr_version = fuse_get_attr_version(fc);
		fuse_read_fill(req, file, file->f_pos, PAGE_SIZE,
			       FUSE_READDIRPLUS);
	} else {
		fuse_read_fill(req, file, file->f_pos, PAGE_SIZE,
			       FUSE_READDIR);
	}
	fuse_request_send(fc, req);
	nbytes = req->out.args[0].size;
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if (plus) {
			err = parse_dirplusfile(page_address(page), nbytes,
						file, dstbuf, filldir,
						attr_version);
		} else {
			err = parse_dirfile(page_address(page), nbytes, file,
					    dstbuf, filldir);
		}
	}

	__free_page(page);
	fuse_invalidate_attr(inode); /* atime changed */
	return err;
}

static char *read_link(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	char *link;

	if (IS_ERR(req))
		return ERR_CAST(req);

	link = (char *) __get_free_page(GFP_KERNEL);
	if (!link) {
		link = ERR_PTR(-ENOMEM);
		goto out;
	}
	req->in.h.opcode = FUSE_READLINK;
	req->in.h.nodeid = get_node_id(inode);
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = PAGE_SIZE - 1;
	req->out.args[0].value = link;
	fuse_request_send(fc, req);
	if (req->out.h.error) {
		free_page((unsigned long) link);
		link = ERR_PTR(req->out.h.error);
	} else
		link[req->out.args[0].size] = '\0';
 out:
	fuse_put_request(fc, req);
	fuse_invalidate_attr(inode); /* atime changed */
	return link;
}

static void free_link(char *link)
{
	if (!IS_ERR(link))
		free_page((unsigned long) link);
}

static void *fuse_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, read_link(dentry));
	return NULL;
}

static void fuse_put_link(struct dentry *dentry, struct nameidata *nd, void *c)
{
	free_link(nd_get_link(nd));
}

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, true);
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	fuse_release_common(file, FUSE_RELEASEDIR);

	return 0;
}

static int fuse_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	return fuse_fsync_common(file, start, end, datasync, 1);
}

static long fuse_dir_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	/* FUSE_IOCTL_DIR only supported for API version >= 7.18 */
	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg, FUSE_IOCTL_DIR);
}

static long fuse_dir_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg,
				 FUSE_IOCTL_COMPAT | FUSE_IOCTL_DIR);
}

static bool update_mtime(unsigned ivalid)
{
	/* Always update if mtime is explicitly set  */
	if (ivalid & ATTR_MTIME_SET)
		return true;

	/* If it's an open(O_TRUNC) or an ftruncate(), don't update */
	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	/* In all other cases update */
	return true;
}

static void iattr_to_fattr(struct iattr *iattr, struct fuse_setattr_in *arg)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = from_kuid(&init_user_ns, iattr->ia_uid);
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = from_kgid(&init_user_ns, iattr->ia_gid);
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && update_mtime(ivalid)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET))
			arg->valid |= FATTR_MTIME_NOW;
	}
}

/*
 * Prevent concurrent writepages on inode
 *
 * This is done by adding a negative bias to the inode write counter
 * and waiting for all pending writes to finish.
 */
void fuse_set_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(!mutex_is_locked(&inode->i_mutex));

	spin_lock(&fc->lock);
	BUG_ON(fi->writectr < 0);
	fi->writectr += FUSE_NOWRITE;
	spin_unlock(&fc->lock);
	wait_event(fi->page_waitq, fi->writectr == FUSE_NOWRITE);
}

/*
 * Allow writepages on inode
 *
 * Remove the bias from the writecounter and send any queued
 * writepages.
 */
static void __fuse_release_nowrite(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(fi->writectr != FUSE_NOWRITE);
	fi->writectr = 0;
	fuse_flush_writepages(inode);
}

void fuse_release_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);

	spin_lock(&fc->lock);
	__fuse_release_nowrite(inode);
	spin_unlock(&fc->lock);
}

/*
 * Set attributes, and at the same time refresh them.
 *
 * Truncation is slightly complicated, because the 'truncate' request
 * may fail, in which case we don't want to touch the mapping.
 * vmtruncate() doesn't allow for this case, so do the rlimit checking
 * and the actual truncation by hand.
 */
int fuse_do_setattr(struct inode *inode, struct iattr *attr,
		    struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	bool is_truncate = false;
	loff_t oldsize;
	int err, success = 0;

	if (!(fc->flags & FUSE_DEFAULT_PERMISSIONS))
		attr->ia_valid |= ATTR_FORCE;

	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_OPEN) {
		if (fc->atomic_o_trunc)
			return 0;
		file = NULL;
	}

	if (attr->ia_valid & ATTR_SIZE)
		is_truncate = true;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (is_truncate) {
		fuse_set_nowrite(inode);
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	}

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(attr, &inarg);
	if (file) {
		struct fuse_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	if (attr->ia_valid & ATTR_SIZE) {
		/* For mandatory locking in truncate */
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = fuse_lock_owner_id(fc, current->files);
	}
	req->in.h.opcode = FUSE_SETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;

	if (fc->iscache && fc->mount_path)
	{
		char *buf = NULL, *path =NULL;
		struct dentry *fuse_dentry;
		struct file *cache_file = NULL;
		fuse_dentry = d_find_alias(inode);
		if(fuse_dentry)
		{
			char *real_path = NULL;
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

			req->out.h.error = cache_file->f_inode->i_op->setattr(cache_file->f_dentry, attr);

			_fuse_copy_attr_to_arg(cache_file, &outarg.attr);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

			dput(fuse_dentry);
		}
	}

	if(!success)
	{
		fuse_request_send(fc, req);
		err = req->out.h.error;
	}
	else
		err = req->out.h.error = 0;
	fuse_put_request(fc, req);
	if (err) {
		if (err == -EINTR)
			fuse_invalidate_attr(inode);
		goto error;
	}

	if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
		make_bad_inode(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fc->lock);
	fuse_change_attributes_common(inode, &outarg.attr,
				      attr_timeout(&outarg));
	oldsize = inode->i_size;
	i_size_write(inode, outarg.attr.size);

	if (is_truncate) {
		/* NOTE: this may release/reacquire fc->lock */
		__fuse_release_nowrite(inode);
	}
	spin_unlock(&fc->lock);

	/*
	 * Only call invalidate_inode_pages2() after removing
	 * FUSE_NOWRITE, otherwise fuse_launder_page() would deadlock.
	 */
	if (S_ISREG(inode->i_mode) && oldsize != outarg.attr.size) {
		truncate_pagecache(inode, outarg.attr.size);
		invalidate_inode_pages2(inode->i_mapping);
	}

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return 0;

error:
	if (is_truncate)
		fuse_release_nowrite(inode);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return err;
}

static int fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = entry->d_inode;
	int error;
	char *full_path;
	int checklist;

	if(check_iscache(inode)){
        full_path = kmalloc(PATH_MAX, GFP_KERNEL);
		translate_path_from_dentry(inode, entry, full_path);
		checklist = check_ACM_share_list_with_path(inode, full_path);
		if(checklist == 0 || checklist == -1){
			kfree(full_path);
			return -EACCES;
		}
		kfree(full_path);
	}

	if (!fuse_allow_current_process(get_fuse_conn(inode)))
		return -EACCES;

	if (attr->ia_valid & ATTR_FILE)
		error = fuse_do_setattr(inode, attr, attr->ia_file);
	else
		error = fuse_do_setattr(inode, attr, NULL);
	
	if (!error && (attr->ia_valid & ATTR_MODE) && !(attr->ia_valid & ATTR_SIZE))
		error = fuse_acl_chmod(entry, inode);
	
	return error;
}

static int fuse_getattr(struct vfsmount *mnt, struct dentry *entry,
			struct kstat *stat)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	//if(entry && strstr(entry->d_iname, "www"))
	//	printk("[%s] file0@%s \n", __func__, entry->d_iname);

	return fuse_update_attributes(inode, stat, NULL, NULL, NULL);
}

int fuse_setxattr(struct dentry *entry, struct inode *inode, const char *name,
			 const void *value, size_t size, int flags)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_setxattr_in inarg;
	int err, success = 0;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	if (fc->iscache && fc->mount_path)
	{
		char *buf = NULL, *path =NULL;
		struct file *cache_file = NULL;
		if(entry)
		{
			char *real_path = NULL;
			path = fuse_prepare_path(fc, entry, buf);
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

			if (S_ISDIR(inode->i_mode))
				cache_file = filp_open(real_path, O_DIRECTORY, 0);
			else
				cache_file = filp_open(real_path, O_RDONLY, 0);

			if (IS_ERR(cache_file))
			{
				printk("[%s] file@%s path@%s real_path@%s\n", __func__, entry->d_iname, path, real_path);
				goto free_cache_normal;
			}

			printk("[%s] file@%s path@%s real_path@%s t11\n", __func__, entry->d_iname, path, real_path);
			cache_file->f_inode->i_op->setxattr(cache_file->f_dentry, name, (void *) value, size, flags);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

			if(success)
			{
				err = 0;
				printk("[%s] file@%s path@%s real_path@%s t11 err@%d sus@%d\n"
					, __func__, entry->d_iname, path, real_path, err, success);
			}
		}
		else
			printk("[%s] no entry\n", __func__);
	}
	
	printk("[%s] WTF111 file@%s sus@%d\n", __func__, entry->d_iname, success);

	if(success == 0)
	{
		printk("[%s] WTF file@%s\n", __func__, entry->d_iname);

		req = fuse_get_req_nopages(fc);
		if (IS_ERR(req))
			return PTR_ERR(req);

		memset(&inarg, 0, sizeof(inarg));
		inarg.size = size;
		inarg.flags = flags;
		req->in.h.opcode = FUSE_SETXATTR;
		req->in.h.nodeid = get_node_id(inode);
		req->in.numargs = 3;
		req->in.args[0].size = sizeof(inarg);
		req->in.args[0].value = &inarg;
		req->in.args[1].size = strlen(name) + 1;
		req->in.args[1].value = name;
		req->in.args[2].size = size;
		req->in.args[2].value = value;
		fuse_request_send(fc, req);
		err = req->out.h.error;
		fuse_put_request(fc, req);
	}

	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err)
		fuse_invalidate_attr(inode);
	return err;
}

ssize_t fuse_getxattr(struct dentry *entry, struct inode *inode, const char *name,
			     void *value, size_t size)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;
	int success = 0;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_GETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	/* This is really two different operations rolled into one */
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = value;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}

	if (fc->iscache && fc->mount_path)
	{
		char *buf = NULL, *path =NULL;
		struct file *cache_file = NULL;
		int need_free = 0;
		if(entry == NULL)
		{
			entry = d_find_alias(inode);
			need_free = 1;

		}

		if(entry)
		{
			char *real_path = NULL;
			path = fuse_prepare_path(fc, entry, buf);
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

			if (S_ISDIR(inode->i_mode))
				cache_file = filp_open(real_path, O_DIRECTORY, 0);
			else
				cache_file = filp_open(real_path, O_RDONLY, 0);

			if (IS_ERR(cache_file))
			{
				printk("[%s] file@%s path@%s real_path@%s\n", __func__, entry->d_iname, path, real_path);
				goto free_cache_normal;
			}

			req->out.h.error = cache_file->f_inode->i_op->getxattr(cache_file->f_dentry, name, (void *) value, size);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

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

	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_getxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static ssize_t fuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;
	int success = 0;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_LISTXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	/* This is really two different operations rolled into one */
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = list;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}

	if (fc->iscache && fc->mount_path)
	{
		char *buf = NULL, *path =NULL;
		struct file *cache_file = NULL;
		ssize_t error;
		if(entry)
		{
			char *real_path = NULL;
			path = fuse_prepare_path(fc, entry, buf);
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

			if (S_ISDIR(inode->i_mode))
				cache_file = filp_open(real_path, O_DIRECTORY, 0);
			else
				cache_file = filp_open(real_path, O_RDONLY, 0);

			if (IS_ERR(cache_file))
			{
				printk("[%s] file@%s path@%s real_path@%s\n", __func__, entry->d_iname, path, real_path);
				goto free_cache_normal;
			}

			printk("[%s] file@%s path@%s real_path@%s t11\n", __func__, entry->d_iname, path, real_path);
			error = cache_file->f_inode->i_op->listxattr(cache_file->f_dentry, list, size);
			req->out.h.error = (error < 0)? error: 0;
			req->out.args[0].size = outarg.size = (error > 0)? error: 0;

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

			if(success)
			{
				printk("[%s] file@%s path@%s real_path@%s t11 err@%ld sus@%d\n"
					, __func__, entry->d_iname, path, real_path, error, success);
			}
		}
		else
			printk("[%s] no entry\n", __func__);
	}

	if(success == 0)
	{
		fuse_request_send(fc, req);
	}
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_listxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

int fuse_removexattr(struct dentry *entry, struct inode *inode, const char *name)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	int err;
	int success = 0;

	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_REMOVEXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = strlen(name) + 1;
	req->in.args[0].value = name;
	if (fc->iscache && fc->mount_path)
	{
		char *buf = NULL, *path =NULL;
		struct file *cache_file = NULL;
		if(entry)
		{
			char *real_path = NULL;
			path = fuse_prepare_path(fc, entry, buf);
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

			if (S_ISDIR(inode->i_mode))
				cache_file = filp_open(real_path, O_DIRECTORY, 0);
			else
				cache_file = filp_open(real_path, O_RDONLY, 0);

			if (IS_ERR(cache_file))
			{
				printk("[%s] file@%s path@%s real_path@%s\n", __func__, entry->d_iname, path, real_path);
				goto free_cache_normal;
			}

			printk("[%s] file@%s path@%s real_path@%s t11\n", __func__, entry->d_iname, path, real_path);
			req->out.h.error = cache_file->f_inode->i_op->removexattr(cache_file->f_dentry, name);

			fput(cache_file);

			success = 1;

free_cache_normal:
			kfree(real_path);
drop_path:
			if(buf)
				kfree(buf);

			if(success)
			{
				err = 0;
				printk("[%s] file@%s path@%s real_path@%s t11 err@%d sus@%d\n"
					, __func__, entry->d_iname, path, real_path, err, success);
			}
		}
		else
			printk("[%s] no entry\n", __func__);
	}

	if(success == 0)
	{
		fuse_request_send(fc, req);
	}
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err)
		fuse_invalidate_attr(inode);
	return err;
}

char *fuse_get_mount_path(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	return fc->mount_path;
}

int check_iscache(struct inode *inode)
{
	struct fuse_conn *fc = NULL;
	if(!IS_ERR(inode)) {
		fc = get_fuse_conn(inode);
		if(!IS_ERR(fc))
				return fc->iscache;
	}
	return 0;
}

void translate_path_from_dentry(struct inode *dir, struct dentry *entry, char *full_path){
	char *path_buf, *fuse_path;
	struct fuse_conn *fc = get_fuse_conn(dir);
	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	strcpy(full_path, fc->mount_path);

	fuse_path = dentry_path_raw(entry, path_buf, PATH_MAX);
	strcat(full_path, fuse_path);

	kfree(path_buf);
}

/* check access controll manage share list */
/* retval  11:compared with permission rw,
		   10:not compared with permission rw,
           01:compared with permission ro,
           00:not compared with permission ro,
*/
int get_check_ret(char *fullpath, char *node_path, int node_permissions){
	int compared = 0, permission = 0;

	/* for level revert rule table, once compare match,
	   or node path include in full path, we should get this rule.*/
	if(strcmp(fullpath, node_path) == 0 || strstr(fullpath, node_path)){
		permission = (node_permissions)? 1:0;
		compared = 1;
	}

	return ((permission << 1) | compared);
}

int check_ACM_share_list(struct inode *inode, const struct path *path){
	char *fullpath, *path_buf;
	int retval = -1;
	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	fullpath = d_path(path, path_buf, PATH_MAX);
	retval = check_ACM_share_list_with_path(inode, fullpath);
	kfree(path_buf);
	return retval;
}

/* retval -1:permission deny,
		   0:ro, 
           1:rw,
           2:nolimit.
*/
int check_ACM_share_list_with_path(struct inode *inode, char *fullpath){
	struct list_head *pos_mnt, *pos_sub;
	shared_bucket_mnt_t *mnt_node;
	shared_bucket_sub_t *sub_node;
	struct fuse_conn *fc = NULL;
	// get open path
	int check_ret, retval = -1, GET_COMPARED_MASK = 0x01, GET_PERMISSION_MASK = 0x02;
	//printk("[%s] vfs_open check_path@%s\n", __func__, fullpath);
	// get fc
	if(!IS_ERR(inode)) {
		fc = get_fuse_conn(inode);
		if(IS_ERR(fc) || !(fc->shared_bucket_list) || IS_ERR(fc->shared_bucket_list))
			return 2; // get fc or bucket_list fail,
	}

	if(list_empty(fc->shared_bucket_list))
		return -1;
	list_for_each(pos_mnt, fc->shared_bucket_list){
		mnt_node = list_entry(pos_mnt, shared_bucket_mnt_t, mnt_list);
		if(mnt_node && !IS_ERR(mnt_node)){
			check_ret = get_check_ret(fullpath, mnt_node->mnt_path, mnt_node->permissions);
			// printk("[%s]cehck_ret@%d\n", __func__, check_ret);
			if(check_ret&GET_COMPARED_MASK){
				retval = (check_ret&GET_PERMISSION_MASK)? 1:0;
				goto FOUND_PATH;
			}

			if(!list_empty(mnt_node->sub_list)){
				// travsersl sibling
				list_for_each(pos_sub, mnt_node->sub_list){
					sub_node = list_entry(pos_sub, shared_bucket_sub_t, sub_list);
					if(sub_node && !IS_ERR(sub_node)){
						check_ret = get_check_ret(fullpath, sub_node->sub_path, sub_node->permissions);
						// printk("[%s]cehck_ret@%d\n",  __func__, check_ret);
						if(check_ret & GET_COMPARED_MASK){
							retval = (check_ret & GET_PERMISSION_MASK)? 1:0;
							goto FOUND_PATH;
						}
					}
				}
			}
		}
	}
FOUND_PATH:
	return retval;
}

int check_allow_write_partial_download(struct inode *inode)
{
	struct fuse_conn *fc = NULL;
	if(!IS_ERR(inode)) {
		fc = get_fuse_conn(inode);
		if(!IS_ERR(fc))
				return fc->support_partial_upload;
	}
	return 0;
}

static const struct inode_operations_wrapper fuse_dir_inode_operations = {
	.ops = {
	.lookup		= fuse_lookup,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename		= fuse_rename,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
	.create		= fuse_create,
	.atomic_open	= fuse_atomic_open,
	.mknod		= fuse_mknod,
	.permission	= fuse_permission,
	.get_acl	= fuse_get_acl,
	.getattr	= fuse_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= generic_removexattr,
	.get_mount_path = fuse_get_mount_path,
	.check_cache = check_iscache,
	.check_partial = check_allow_write_partial_download,
	},
	.rename2	= fuse_rename2,
};

static const struct file_operations fuse_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
	.fsync		= fuse_dir_fsync,
	.unlocked_ioctl	= fuse_dir_ioctl,
	.compat_ioctl	= fuse_dir_compat_ioctl,
};

static const struct inode_operations fuse_common_inode_operations = {
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
	.get_acl	= fuse_get_acl,
	.getattr	= fuse_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= generic_removexattr,
	.get_mount_path = fuse_get_mount_path,
	.check_cache = check_iscache,
	.update_dirty = update_dirty,
	.check_partial = check_allow_write_partial_download,
};

static const struct inode_operations fuse_symlink_inode_operations = {
	.setattr	= fuse_setattr,
	.follow_link	= fuse_follow_link,
	.put_link	= fuse_put_link,
	.readlink	= generic_readlink,
	.get_acl	= fuse_get_acl,
	.getattr	= fuse_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= generic_removexattr,
};

void fuse_init_common(struct inode *inode)
{
	inode->i_op = &fuse_common_inode_operations;
}

void fuse_init_dir(struct inode *inode)
{
	inode->i_op = &fuse_dir_inode_operations.ops;
	inode->i_fop = &fuse_dir_operations;
	inode->i_flags |= S_IOPS_WRAPPER;
}

void fuse_init_symlink(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
}
