#include "fuse_i.h"

static int fuse_xattr_get(struct dentry *entry, const char *name,
			     void *value, size_t size, int xflags)
{
	struct inode *inode = entry->d_inode;
	return fuse_getxattr(inode, name, value, size);
}

static int fuse_xattr_set(struct dentry *entry, const char *name,
			    const void *value, size_t size, int flags, int xflags)
{
	struct inode *inode = entry->d_inode;
	if (!value)
		return fuse_removexattr(inode, name);
		
	return fuse_setxattr(inode, name, value, size, flags);
}

static const struct xattr_handler fuse_xattr_handler = {
	.prefix	= "",
	.flags	= 0,
	.get	= fuse_xattr_get,
	.set	= fuse_xattr_set,
};

const struct xattr_handler *fuse_xattr_handlers[] = {
#if defined(CONFIG_XFS_POSIX_ACL) || defined(CONFIG_EXT4_FS_POSIX_ACL) || defined(CONFIG_BTRFS_FS_POSIX_ACL)
	&fuse_xattr_acl_access_handler,
	&fuse_xattr_acl_default_handler,
#endif
	&fuse_xattr_handler,
	NULL
};
