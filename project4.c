/*
 * Demonstrate a trivial filesystem using libfs.
 *
 * Copyright 2002, 2003 Jonathan Corbet <corbet@lwn.net>
 * This file may be redistributed under the terms of the GNU GPL.
 *
 * Chances are that this code will crash your system, delete your
 * nethack high scores, and set your disk drives on fire.  You have
 * been warned.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>	/* copy_to_user */
#include <asm/atomic.h>

/*
 * Boilerplate stuff.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abhishek Chauhan");

#define LFS_MAGIC 0x19980122


/*
 * Anytime we make a file or directory in our filesystem we need to
 * come up with an inode to represent it internally.  This is
 * the function that does that job.  All that's really interesting
 * is the "mode" parameter, which says whether this is a directory
 * or file, and gives the permissions.
 */
static struct inode *lfs_make_inode(struct super_block *sb, int mode)
{
	struct inode *ret = new_inode(sb);

	if (ret) {
		ret->i_ino = get_next_ino();
		ret->i_mode = mode;
	//	ret->i_uid = 0;
	//	ret->i_gid = 0;
		ret->i_blocks = 0;
		ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
	}
	return ret;
}


/*
 * The operations on our "files".
 */

/*
 * Open a file.  All we have to do here is to copy over a
 * copy of the counter pointer so it's easier to get at.
 */
static int lfs_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

#define TMPSIZE 20
/*
 * Read a file.  Here we increment and read the counter, then pass it
 * back to the caller.  The increment only happens if the read is done
 * at the beginning of the file (offset = 0); otherwise we end up counting
 * by twos.
 */

#define MAX_INFO 256
static char *task_state[] = {"TASK_UNRUNNABLE", "TASK_RUNNABLE",
			"TASK_STOPPED"};
static char *task_type[] = {"KERNEL_THREAD", "USER_THREAD"};

static ssize_t lfs_read_thread_file(struct file *filp, char *buf,
		size_t count, loff_t *offset)
{
	char tmp[TASK_COMM_LEN];
	char buffer[MAX_INFO];
	struct task_struct *task = (struct task_struct *) filp->private_data;
	int type = 0;
	int state = 0;
	int length;

	if (*offset != 0)
		return 0;

	if (task->mm)
		type = 1;

	if (task->state > 0)
		state = 2;
	else if (task->state < 0)
		state = 0;
	else
		state = 1;

	get_task_comm(tmp, task);

	length = snprintf(buffer, 1024, "State: %s\nType: %s\nCpu: %d\nMonotonic Start time %lluNS\nName: %s\nStack: 0x%p\n",
		 task_state[state],
		 task_type[type],
		 task_thread_info(task)->cpu,
		 task->start_time,
		 tmp,
		 task->stack);


	if (copy_to_user(buf, buffer, length))
		return -EFAULT;

	*offset += length;
	return length;
}

static ssize_t lfs_write_thread_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset)
{
	return -EINVAL;
}

static ssize_t lfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset)
{
	return 0;
}

static ssize_t lfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset)
{
	struct task_struct *task = (struct task_struct *) filp->private_data;
	char tmp[TMPSIZE];
	struct siginfo info;
	int sig_num;
	int ret;

	if (*offset != 0)
		return -EINVAL;

	memset(tmp, 0, TMPSIZE);
	if (copy_from_user(tmp, buf, count))
		return -EINVAL;

	sig_num = (int)simple_strtol(tmp, NULL, 10);
	info.si_signo = sig_num;
	info.si_code = SI_USER;
	info.si_errno = 0;
	info.si_int = 1234;
	info.si_pid = 0;
	info.si_uid = 0;

	ret = send_sig_info(sig_num, &info, task);
	if (ret < 0) {
		printk(KERN_ERR "Signal %d sending failed for PID %d TID %d\n",
		       sig_num,task->tgid, task->pid);
		return ret;
	}
	printk(KERN_INFO "Signal %d delivered for PID %d TID %d\n",
	       sig_num,task->tgid, task->pid);

	return count;
}


/*
static ssize_t lfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset)
{
	atomic_t *counter = (atomic_t *) filp->private_data;
	int v, len;
	char tmp[TMPSIZE];
	v = atomic_read(counter);
	if (*offset > 0)
		v -= 1; 
	else
		atomic_inc(counter);
	len = snprintf(tmp, TMPSIZE, "%d\n", v);
	if (*offset > len)
		return 0;
	if (count > len - *offset)
		count = len - *offset;
	if (copy_to_user(buf, tmp + *offset, count))
		return -EFAULT;
	*offset += count;
	return count;
}

static ssize_t lfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset)
{
	atomic_t *counter = (atomic_t *) filp->private_data;
	char tmp[TMPSIZE];
	if (*offset != 0)
		return -EINVAL;
	if (count >= TMPSIZE)
		return -EINVAL;
	memset(tmp, 0, TMPSIZE);
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	atomic_set(counter, simple_strtol(tmp, NULL, 10));
	return count;
}
*/
int lfs_release (struct inode *inode, struct file *filep)
{
	//kfree(inode->i_private);
	return 0;
}

/*
 * Now we can put together our file operations structure.
 */
static struct file_operations lfs_file_ops = {
	.open	= lfs_open,
	.read	= lfs_read_file,
	.write  = lfs_write_file,
	.release  = lfs_release
};

static struct file_operations lfs_thread_file_ops = {
	.open	= lfs_open,
	.read	= lfs_read_thread_file,
	.write  = lfs_write_thread_file,
	.release  = lfs_release
};

/*
 * Create a file mapping a name to a counter.
 */
static struct dentry *lfs_create_file (struct super_block *sb,
		struct dentry *dir, const char *name,
		int thread_file, void *priv_data)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;
/*
 * Make a hashed version of the name to go with the dentry.
 */
	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(name, qname.len);
/*
 * Now we can create our dentry and the inode to go with it.
 */
	dentry = d_alloc(dir, &qname);
	if (! dentry)
		goto out;
	inode = lfs_make_inode(sb, S_IFREG | 0644);
	if (! inode)
		goto out_dput;

	if (thread_file)
		inode->i_fop = &lfs_thread_file_ops;
	else
		inode->i_fop = &lfs_file_ops;

	inode->i_private = priv_data;

/*
 * Put it all into the dentry cache and we're done.
 */
	d_add(dentry, inode);
	return dentry;
/*
 * Then again, maybe it didn't work.
 */
  out_dput:
	dput(dentry);
  out:
	return 0;
}


/*
 * Create a directory which can be used to hold files.  This code is
 * almost identical to the "create file" logic, except that we create
 * the inode with a different mode, and use the libfs "simple" operations.
 */
static struct dentry *lfs_create_dir (struct super_block *sb,
		struct dentry *parent, const char *name)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;

	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(name, qname.len);
	dentry = d_alloc(parent, &qname);
	if (! dentry)
		goto out;

	inode = lfs_make_inode(sb, S_IFDIR | 0644);
	if (! inode)
		goto out_dput;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;

	d_add(dentry, inode);
	return dentry;

  out_dput:
	dput(dentry);
  out:
	return 0;
}


void project4fs_create_directory(struct super_block *sb,
				 struct dentry *root, struct task_struct *task,
				 int process_threads)
{
	struct list_head *list;
	struct task_struct *child;
	struct task_struct *thrd = task;
	struct dentry *mydir;
	char buffer[30];

	if (!task)
		return;

	//printk(KERN_INFO "Running for gid %d pid %d\n", task->tgid, task->pid);
	snprintf(buffer, 20, "%d",task->pid);

	mydir = lfs_create_dir(sb, root, buffer);

	if (!mydir) {
		printk(KERN_ERR
			"failed to create directory for %s\n", buffer);
		return;
	}

	lfs_create_file(sb, mydir, "signal", 0, task);
	snprintf(buffer, 20, "%d.status",task->pid);
	lfs_create_file(sb, mydir, buffer, 1, task);

	if (process_threads) {
		while_each_thread(task, thrd) {
			project4fs_create_directory(sb, root, thrd, 0);
		};
	}

	list_for_each(list, &task->children) {

		child = list_entry(list, struct task_struct, sibling);

		project4fs_create_directory(sb, mydir, child, 1);
	}
}

static void lfs_create_files (struct super_block *sb, struct dentry *root)
{
	project4fs_create_directory(sb, root, &init_task, 1);
}



/*
 * Superblock stuff.  This is all boilerplate to give the vfs something
 * that looks like a filesystem to work with.
 */

/*
 * Our superblock operations, both of which are generic kernel ops
 * that we don't have to write ourselves.
 */
static struct super_operations lfs_s_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
};

/*
 * "Fill" a superblock with mundane stuff.
 */
static int lfs_fill_super (struct super_block *sb, void *data, int silent)
{
	struct inode *root;
	struct dentry *root_dentry;
/*
 * Basic parameters.
 */
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = LFS_MAGIC;
	sb->s_op = &lfs_s_ops;
/*
 * We need to conjure up an inode to represent the root directory
 * of this filesystem.  Its operations all come from libfs, so we
 * don't have to mess with actually *doing* things inside this
 * directory.
 */
	root = lfs_make_inode (sb, S_IFDIR | 0755);
	if (! root)
		goto out;
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;
/*
 * Get a dentry to represent the directory in core.
 */
	root_dentry = d_make_root(root);
	if (! root_dentry)
		goto out_iput;
	sb->s_root = root_dentry;
/*
 * Make up the files which will be in this filesystem, and we're done.
 */
	lfs_create_files (sb, root_dentry);
	return 0;
	
  out_iput:
	iput(root);
  out:
	return -ENOMEM;
}


/*
 * Stuff to pass in when registering the filesystem.
 */
static struct dentry *lfs_get_super(struct file_system_type *fst,
		int flags, const char *devname, void *data)
{
	return mount_nodev(fst, flags, data, lfs_fill_super);
}

static struct file_system_type lfs_type = {
	.owner 		= THIS_MODULE,
	.name		= "project4",
	.mount		= lfs_get_super,
	.kill_sb	= kill_litter_super,
};

/*
 * Get things set up.
 */
static int __init lfs_init(void)
{
	return register_filesystem(&lfs_type);
}

static void __exit lfs_exit(void)
{
	unregister_filesystem(&lfs_type);
}

module_init(lfs_init);
module_exit(lfs_exit);

