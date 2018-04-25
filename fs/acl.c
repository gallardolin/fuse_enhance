#include "fuse_i.h"

#include <linux/posix_acl_xattr.h>

static const char* __fuse_acl_type_name(int type)
{
	const char *name;
	
	switch (type) {
		case ACL_TYPE_ACCESS:
			name = XATTR_NAME_POSIX_ACL_ACCESS;
			break;
		case ACL_TYPE_DEFAULT:
			name = XATTR_NAME_POSIX_ACL_DEFAULT;
			break;
		default:
			name = NULL;
			break;
	}
	return name;
}

/*
* fuse only need to update its mode when accesses its acl
* , because its lower file system will update by itself.
*/
static int fuse_set_mode(struct inode *inode, umode_t mode)
{
	int error = 0;
	
	if (mode != inode->i_mode) {
		struct fuse_conn *fc = get_fuse_conn(inode);
		struct iattr attr;
		attr.ia_valid = ATTR_MODE | ATTR_CTIME;
		attr.ia_mode = mode;
		attr.ia_ctime = current_fs_time(inode->i_sb);
		
		if (!(fc->flags & FUSE_DEFAULT_PERMISSIONS))
			attr.ia_valid |= ATTR_FORCE;

		error = inode_change_ok(inode, &attr);
		if (!error)
		{
			inode->i_mode = (inode->i_mode & S_IFMT) | (attr.ia_mode & 07777);
			inode->i_ctime = attr.ia_ctime;
		}
	}
	return error;
}

struct posix_acl *fuse_get_acl(struct inode *inode, int type)
{
	struct posix_acl *acl;
	const char *name = __fuse_acl_type_name(type);
	void *value = NULL;
	int size;
	
	if (!name)
		return ERR_PTR(-EOPNOTSUPP);
	
	if (inode && (!(inode->i_op->check_cache && inode->i_op->check_cache(inode) == 1)))
	{
		acl = get_cached_acl(inode, type);
		if (acl != ACL_NOT_CACHED)
			return acl;
	}
	
	
	/* get the buffer size of extended attribute */
	size = fuse_getxattr(inode, name, NULL, 0);
	if (size <= 0)
		return NULL;
	
	value = kmalloc(size, GFP_KERNEL);
	if (!value)
		return ERR_PTR(-ENOMEM);
	
	size = fuse_getxattr(inode, name, value, size);
	if (size > 0) {
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (acl && !IS_ERR(acl))
		{
			if (inode && (!(inode->i_op->check_cache && inode->i_op->check_cache(inode) == 1)))
				set_cached_acl(inode, type, acl);
		}
	}
	else if ((size == 0) || (size == -ENODATA))
		acl = NULL;
	else if (size == -ERANGE)
		acl = ERR_PTR(-E2BIG);
	else
		acl = ERR_PTR(size);
	
	kfree(value);
	return acl;
}

static int fuse_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	const char *name = __fuse_acl_type_name(type);
	int error;
	
	if(!name)
		return -EINVAL; 
	
	if (acl) {
		void *value;
		size_t size = posix_acl_xattr_size(acl->a_count);
		
		value = kmalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;
		
		posix_acl_to_xattr(&init_user_ns, acl, value, size);
		error = fuse_setxattr(inode, name, value, size, 0);
		kfree(value);
	}
	else
		error = fuse_removexattr(inode, name);
	
	if (!error)
	{
		if (inode && (!(inode->i_op->check_cache && inode->i_op->check_cache(inode) == 1)))
			set_cached_acl(inode, type, acl);
	}
	
	return error;
}

int fuse_inherit_acl(struct inode *inode, struct posix_acl *acl)
{
	umode_t mode = inode->i_mode;
	int error = 0;
	
	if (!acl)
		goto out_release;
	if (S_ISDIR(inode->i_mode)) {
		error = fuse_set_acl(inode, acl, ACL_TYPE_DEFAULT);
		if (error)
			goto out_release;
	}
	
	error = posix_acl_create(&acl, GFP_KERNEL, &mode);
	if (error < 0)
		return error;
	
	error = fuse_set_mode(inode, mode);
	if (error)
		goto out_release;

	error = fuse_set_acl(inode, acl, ACL_TYPE_ACCESS);
out_release:
	posix_acl_release(acl);
	return error;
}

int fuse_acl_chmod(struct inode *inode)
{
	struct posix_acl *acl;
	int error;
	
	acl = fuse_get_acl(inode, ACL_TYPE_ACCESS);
	if (IS_ERR(acl) || !acl)
		return PTR_ERR(acl);
	
	error = posix_acl_chmod(&acl, GFP_KERNEL, inode->i_mode);
	if (error)
		return error;
	
	error = fuse_set_acl(inode, acl, ACL_TYPE_ACCESS);
	posix_acl_release(acl);
	return error;
}

static int fuse_xattr_acl_get(struct dentry *entry, const char *name,
			     void *value, size_t size, int type)
{
	struct inode *inode = entry->d_inode;
	struct posix_acl *acl;
	int error;
	
	/* First, get ACL from cache */
	if (inode && (inode->i_op->check_cache && inode->i_op->check_cache(inode) == 1))
		goto IS_CACHE_FLOW;

	acl = get_cached_acl(inode, type);
	
	if(acl == NULL)
	{
		error = -ENODATA;
	}
	else if (acl != ACL_NOT_CACHED && !IS_ERR(acl)) {
		error = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		posix_acl_release(acl);
	}
	else {
IS_CACHE_FLOW:
		/*
		 * There is no cached ACL, get from extended attribute.
		 * If the ACL is valid, cache it.
		 */
		name = __fuse_acl_type_name(type);
		error = name ? fuse_getxattr(inode, name, value, size) : -EINVAL;
		
		acl = error < 0 ? NULL : posix_acl_from_xattr(&init_user_ns, value, size);
		if (acl && !IS_ERR(acl)) {
			if (!posix_acl_valid(acl))
			{
				if (inode && (!(inode->i_op->check_cache && inode->i_op->check_cache(inode) == 1)))
					set_cached_acl(inode, type, acl);
			}
			posix_acl_release(acl);
		}
	}
	return error;
}

static int fuse_xattr_acl_set(struct dentry *entry, const char *name,
			    const void *value, size_t size, int flags, int type)
{
	struct inode *inode = entry->d_inode;
	struct posix_acl *acl = NULL;
	int error;
	
	if (type == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode))
		return value ? -EACCES : 0;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	
	if (!value)
		return fuse_set_acl(inode, acl, type);
	
	acl = posix_acl_from_xattr(&init_user_ns, value, size);
	if (!acl || IS_ERR(acl))
		return PTR_ERR(acl);
	
	error = posix_acl_valid(acl);
	if (error)
		goto out_release;
	
	name = __fuse_acl_type_name(type);
	error = name ? fuse_setxattr(inode, name, value, size, flags) : -EINVAL;
	if (error)
		goto out_release;
	
	if (inode && (!(inode->i_op->check_cache && inode->i_op->check_cache(inode) == 1)))
		set_cached_acl(inode, type, acl);
	
	if (type == ACL_TYPE_ACCESS) {
		umode_t mode = inode->i_mode;
		error = posix_acl_equiv_mode(acl, &mode);
		if (error < 0)
			goto out_release;
		
		/* setattr to chmod */
		error = fuse_set_mode(inode, mode);
		if (error)
			goto out_release;
	}
out_release:
	posix_acl_release(acl);
	return error;
}

const struct xattr_handler fuse_xattr_acl_access_handler = {
	.prefix	= POSIX_ACL_XATTR_ACCESS,
	.flags	= ACL_TYPE_ACCESS,
	.get	= fuse_xattr_acl_get,
	.set	= fuse_xattr_acl_set,
};

const struct xattr_handler fuse_xattr_acl_default_handler = {
	.prefix	= POSIX_ACL_XATTR_DEFAULT,
	.flags	= ACL_TYPE_DEFAULT,
	.get	= fuse_xattr_acl_get,
	.set	= fuse_xattr_acl_set,
};
