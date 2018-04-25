/*
 *  linux/fs/readdir.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/dirent.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

#include <asm/uaccess.h>

#include "internal.h"

#define YAS3FS_FOLDER_DEMAN	   _IOW('F', 4, int)
#define YAS3FS_LSBUFFER_MAX    16

int vfs_readdir(struct file *file, filldir_t filler, void *buf)
{
	struct inode *inode = file_inode(file);
	struct inode *cache_inode = NULL;
	struct file *cache_file = NULL;
	char *path, *full_path, *real_path, *lastoff;
	int *arg;
	loff_t		offset = 0, entoff;
	int res = -ENOTDIR;
	mm_segment_t		oldfs;
	bool inited = false;

	if (!file->f_op || !file->f_op->readdir)
		goto out;

	if (inode->i_op->check_cache && inode->i_op->check_cache(inode) == 1)
	{
		lastoff = (char *) kmalloc(YAS3FS_LSBUFFER_MAX + 1, GFP_KERNEL);

		if (!lastoff)
			goto normal_readdir;
		
		memset(lastoff, 0, YAS3FS_LSBUFFER_MAX + 1);

		path = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!path)
			goto free_offset;

		memset(path, 0, PATH_MAX);
		full_path = d_path(&(file->f_path), path, PATH_MAX);

		if (!full_path)
			goto free_path_normal;

		real_path = path_translate(full_path);
		if (!real_path)
			goto free_path_normal;

		cache_file = filp_open(real_path, file->f_flags, file->f_mode);
		if (IS_ERR(cache_file))
			goto free_cache_normal;

		cache_inode = file_inode(cache_file);;

		offset = vfs_llseek(cache_file, file->f_pos, SEEK_SET);
		if (offset < 0)
			goto close_normal;

		res = cache_inode->i_op->getxattr(cache_file->f_dentry, "user.lsvalue", (void *) lastoff, YAS3FS_LSBUFFER_MAX);
		if (res < 0)
			inited = true;
		else
		{
			res = kstrtoll(lastoff, 16, &entoff);
			if (res < 0)
				inited = true;
			else
			{
				if (file->f_pos >= entoff)
				{
					vfs_llseek(file, 0, SEEK_END);
					fput(cache_file);
					kfree(real_path);
					kfree(path);
					kfree(lastoff);
					res = 0;
					goto out;
				}
			}
		}

		res = security_file_permission(cache_file, MAY_READ);
		if (res)
			goto close_normal;

		arg = kmalloc(sizeof(int), GFP_USER);
		if (!arg)
			goto close_normal;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		if (file->f_pos == 0)
		{
			res = file->f_op->unlocked_ioctl(file, YAS3FS_FOLDER_DEMAN, (unsigned long) arg);
			if (res < 0)
			{
				set_fs(oldfs);
				kfree(arg);
				fput(cache_file);
				kfree(real_path);
				kfree(path);
				kfree(lastoff);

				goto out;
			}
		}
		set_fs(oldfs);
		kfree(arg);

		res = mutex_lock_killable(&cache_inode->i_mutex);
		if (res)
			goto close_normal;

		res = -ENOENT;
		if (!IS_DEADDIR(cache_inode))
		{
			res = cache_file->f_op->readdir(cache_file, buf, filler);
			file_accessed(cache_file);
		}
		offset = vfs_llseek(cache_file, 0, SEEK_CUR);
		offset = vfs_llseek(file, offset, SEEK_SET);
		if (offset < 0)
			printk("vfs_llseek offset less than zero \n");
		mutex_unlock(&cache_inode->i_mutex);
		fput(cache_file);
		kfree(real_path);
		kfree(path);
		kfree(lastoff);
		goto out;

close_normal:
		fput(cache_file);
free_cache_normal:
		kfree(real_path);
free_path_normal:
		kfree(path);
free_offset:
		kfree(lastoff);
	}

normal_readdir:
	res = security_file_permission(file, MAY_READ);
	if (res)
		goto out;

	res = mutex_lock_killable(&inode->i_mutex);
	if (res)
		goto out;

	res = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		res = file->f_op->readdir(file, buf, filler);
		file_accessed(file);
	}
	mutex_unlock(&inode->i_mutex);
out:
	return res;
}

EXPORT_SYMBOL(vfs_readdir);

/*
 * Traditional linux readdir() handling..
 *
 * "count=1" is a special case, meaning that the buffer is one
 * dirent-structure in size and that the code can't handle more
 * anyway. Thus the special "fillonedir()" function for that
 * case (the low-level handlers don't need to care about this).
 */

#ifdef __ARCH_WANT_OLD_READDIR

struct old_linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_offset;
	unsigned short	d_namlen;
	char		d_name[1];
};

struct readdir_callback {
	struct old_linux_dirent __user * dirent;
	int result;
};

static int fillonedir(void * __buf, const char * name, int namlen, loff_t offset,
		      u64 ino, unsigned int d_type)
{
	struct readdir_callback * buf = (struct readdir_callback *) __buf;
	struct old_linux_dirent __user * dirent;
	unsigned long d_ino;

	if (buf->result)
		return -EINVAL;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->result = -EOVERFLOW;
		return -EOVERFLOW;
	}
	buf->result++;
	dirent = buf->dirent;
	if (!access_ok(VERIFY_WRITE, dirent,
			(unsigned long)(dirent->d_name + namlen + 1) -
				(unsigned long)dirent))
		goto efault;
	if (	__put_user(d_ino, &dirent->d_ino) ||
		__put_user(offset, &dirent->d_offset) ||
		__put_user(namlen, &dirent->d_namlen) ||
		__copy_to_user(dirent->d_name, name, namlen) ||
		__put_user(0, dirent->d_name + namlen))
		goto efault;
	return 0;
efault:
	buf->result = -EFAULT;
	return -EFAULT;
}

SYSCALL_DEFINE3(old_readdir, unsigned int, fd,
		struct old_linux_dirent __user *, dirent, unsigned int, count)
{
	int error;
	struct fd f = fdget(fd);
	struct readdir_callback buf;

	if (!f.file)
		return -EBADF;

	buf.result = 0;
	buf.dirent = dirent;

	error = vfs_readdir(f.file, fillonedir, &buf);
	if (buf.result)
		error = buf.result;

	fdput(f);
	return error;
}

#endif /* __ARCH_WANT_OLD_READDIR */

/*
 * New, all-improved, singing, dancing, iBCS2-compliant getdents()
 * interface. 
 */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct getdents_callback {
	struct linux_dirent __user * current_dir;
	struct linux_dirent __user * previous;
	int count;
	int error;
};

static int filldir(void * __buf, const char * name, int namlen, loff_t offset,
		   u64 ino, unsigned int d_type)
{
	struct linux_dirent __user * dirent;
	struct getdents_callback * buf = (struct getdents_callback *) __buf;
	unsigned long d_ino;
	int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + namlen + 2,
		sizeof(long));

	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->error = -EOVERFLOW;
		return -EOVERFLOW;
	}
	dirent = buf->previous;
	if (dirent) {
		if (__put_user(offset, &dirent->d_off))
			goto efault;
	}
	dirent = buf->current_dir;
	if (__put_user(d_ino, &dirent->d_ino))
		goto efault;
	if (__put_user(reclen, &dirent->d_reclen))
		goto efault;
	if (copy_to_user(dirent->d_name, name, namlen))
		goto efault;
	if (__put_user(0, dirent->d_name + namlen))
		goto efault;
	if (__put_user(d_type, (char __user *) dirent + reclen - 1))
		goto efault;
	buf->previous = dirent;
	dirent = (void __user *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;
efault:
	buf->error = -EFAULT;
	return -EFAULT;
}

SYSCALL_DEFINE3(getdents, unsigned int, fd,
		struct linux_dirent __user *, dirent, unsigned int, count)
{
	struct fd f;
	struct linux_dirent __user * lastdirent;
	struct getdents_callback buf;
	int error;

	if (!access_ok(VERIFY_WRITE, dirent, count))
		return -EFAULT;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	buf.current_dir = dirent;
	buf.previous = NULL;
	buf.count = count;
	buf.error = 0;

	error = vfs_readdir(f.file, filldir, &buf);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		if (put_user(f.file->f_pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput(f);
	return error;
}

struct getdents_callback64 {
	struct linux_dirent64 __user * current_dir;
	struct linux_dirent64 __user * previous;
	int count;
	int error;
};

static int filldir64(void * __buf, const char * name, int namlen, loff_t offset,
		     u64 ino, unsigned int d_type)
{
	struct linux_dirent64 __user *dirent;
	struct getdents_callback64 * buf = (struct getdents_callback64 *) __buf;
	int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
		sizeof(u64));

	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	dirent = buf->previous;
	if (dirent) {
		if (__put_user(offset, &dirent->d_off))
			goto efault;
	}
	dirent = buf->current_dir;
	if (__put_user(ino, &dirent->d_ino))
		goto efault;
	if (__put_user(0, &dirent->d_off))
		goto efault;
	if (__put_user(reclen, &dirent->d_reclen))
		goto efault;
	if (__put_user(d_type, &dirent->d_type))
		goto efault;
	if (copy_to_user(dirent->d_name, name, namlen))
		goto efault;
	if (__put_user(0, dirent->d_name + namlen))
		goto efault;
	buf->previous = dirent;
	dirent = (void __user *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;
efault:
	buf->error = -EFAULT;
	return -EFAULT;
}

SYSCALL_DEFINE3(getdents64, unsigned int, fd,
		struct linux_dirent64 __user *, dirent, unsigned int, count)
{
	struct fd f;
	struct linux_dirent64 __user * lastdirent;
	struct getdents_callback64 buf;
	int error;

	if (!access_ok(VERIFY_WRITE, dirent, count))
		return -EFAULT;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	buf.current_dir = dirent;
	buf.previous = NULL;
	buf.count = count;
	buf.error = 0;

	error = vfs_readdir(f.file, filldir64, &buf);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		typeof(lastdirent->d_off) d_off = f.file->f_pos;
		if (__put_user(d_off, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput(f);
	return error;
}
