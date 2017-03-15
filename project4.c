/* Project4.c
 *
 * Virtual File System for Project 4
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>

#define PROJECT4_MAGIC 0xDEADBEEF
#define TMPSIZE 20
#define MAX_INFO 256

enum project4_entry_type {
	DIRECTORY,
	SIGNAL_FILE,
	STATUS_FILE
};

static char *task_state[] = {"TASK_UNRUNNABLE", "TASK_RUNNABLE",
				"TASK_STOPPED"};

static char *task_type[] = {"KERNEL_THREAD", "USER_THREAD"};

static struct inode *project4_make_inode(struct super_block *sb, int mode)
{
	struct inode *ret = new_inode(sb);

	if (ret) {
		ret->i_ino = get_next_ino();
		ret->i_mode = mode;
		ret->i_blocks = 0;
		ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
	}
	return ret;
}

static int project4_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

static ssize_t project4_read_thread_file(struct file *filp, char *buf,
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

/**
 * @brief Called for write of Status file
 *
 * @param filp NOT USED
 * @param buf NOT USED
 * @param count NOT USED
 * @param offset NOT USED
 *
 * @return  Always -EINVAL
 */
static ssize_t project4_write_thread_file(struct file *filp, const char *buf,
					  size_t count, loff_t *offset)
{
	/* Writing Status File is not supported */
	return -EINVAL;
}

/**
 * @brief Called for read of Signal file
 *
 * @param filp NOT USED
 * @param buf NOT USED
 * @param count NOT USED
 * @param offset NOT USED
 *
 * @return  Always -EINVAL
 */
static ssize_t project4_read_file(struct file *filp, char *buf,
				  size_t count, loff_t *offset)
{
	/* Reading Signal File is not supported */
	return -EINVAL;
}

static ssize_t project4_write_file(struct file *filp, const char *buf,
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

/**
 * @brief Called during release of file
 *
 * @param inode Inode for the File
 * @param filep File Pointer for the File
 *
 * @return 0 Always
 */
int project4_release (struct inode *inode, struct file *filep)
{
	return 0;
}

/**
 * @brief FIle operations for the Signal files
 */
static struct file_operations project4_file_ops = {
	.open	= project4_open,
	.read	= project4_read_file,
	.write  = project4_write_file,
	.release  = project4_release
};

/**
 * @brief File Operations for the Status files
 */
static struct file_operations project4_thread_file_ops = {
	.open	= project4_open,
	.read	= project4_read_thread_file,
	.write  = project4_write_thread_file,
	.release  = project4_release
};

/**
 * @brief Creates a file/dir entry in filesystem
 *
 * @param sb Super-Block for the filesystem
 * @param parent Parent Directory
 * @param name Name of the entry
 * @param type Type of the entry
 * @param priv_data Priv-Data associated with entry
 *
 * @return NULL if failed, otherwise dentry pointer
 */
static struct dentry *project4_create_entry(struct super_block *sb,
					    struct dentry *parent,
					    const char *name,
					    enum project4_entry_type type,
					    void *priv_data)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;
	int mode;

	/* Quick String for dentry */
	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(name, qname.len);

	/* Allocated an dentry */
	dentry = d_alloc(parent, &qname);
	if (!dentry) {
		printk(KERN_ERR "dentry allocation failed\n");
		return NULL;
	}

	/* Set the modes for inode */
	switch (type) {
		case DIRECTORY:
			mode = S_IFDIR | 0644;
			break;
		case SIGNAL_FILE:
		case STATUS_FILE:
			mode = S_IFREG | 0644;
			break;
		default:
			printk(KERN_ERR "Unknown entry requested to create\n");
			return NULL;
	}

	/* Allocate inode for the entry */
	inode = project4_make_inode(sb, mode);
	if (!inode) {
		printk(KERN_ERR "inode allocation failed\n");
		dput(dentry);
		return NULL;
	}

	/* Registers file operations/inode operations */
	switch (type) {
		case DIRECTORY:
			inode->i_op = &simple_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;
			break;
		case SIGNAL_FILE:
			inode->i_fop = &project4_file_ops;
			inode->i_private = priv_data;
			break;
		case STATUS_FILE:
			inode->i_fop = &project4_thread_file_ops;
			inode->i_private = priv_data;
			break;
	}

	/* Add dentry to hash queue*/
	d_add(dentry, inode);

	return dentry;
}

/**
 * @brief Recursively create entire process/thread hierarchy
 *
 * @param sb Super-Block for the fs
 * @param root Root dentry for the fs
 * @param task Task Structure Pointer for root process
 * @param create_threads 1 for creating sibling thread dirs, 0 for not
 *
 * @return 0 for success, -ENOMEM on failure
 */
int project4fs_create_hierarchy(struct super_block *sb,
				 struct dentry *root, struct task_struct *task,
				 int create_threads)
{
	struct list_head *list;
	struct task_struct *child;
	struct task_struct *thrd = task;
	struct dentry *mydir;
	struct dentry *myfile;
	char buffer[30];
	int ret;

	/* Base case for the recursive function */
	if (!task)
		return 0;

	/* Create String from pid */
	snprintf(buffer, 20, "%d",task->pid);

	/* Create directory with pid */
	mydir = project4_create_entry(sb, root, buffer, DIRECTORY, NULL);

	if (!mydir) {
		printk(KERN_ERR
		       "failed to create directory for %s\n", buffer);
		return -ENOMEM;
	}

	/* Create Signal file inside the pid directory */
	myfile =project4_create_entry(sb, mydir, "signal", SIGNAL_FILE, task);
	if (!myfile) {
		printk(KERN_ERR
		       "failed to create signal file \n");
		return -ENOMEM;
	}

	/* Create String from status file */
	snprintf(buffer, 20, "%d.status",task->pid);

	/* Create Status file inside the pid directory */
	myfile = project4_create_entry(sb, mydir, buffer, STATUS_FILE, task);
	if (!myfile) {
		printk(KERN_ERR
		       "failed to create status file  %s\n", buffer);
		return -ENOMEM;
	}

	/* Only the first process will create the directory for all threads in
	 * the thread group. This is requried to avoid multiple calls to same
	 * thread as the thread-group list is double link list without any start
	 * and end
	 */
	if (create_threads) {
		while_each_thread(task, thrd) {
			/* Create at same hierarchy */
			ret = project4fs_create_hierarchy(sb, root, thrd, 0);
			if (ret)
				return ret;
		};
	}

	/* Iterate across all the child. The children list does not contain the list
	 * of all threads for a given parent. Hence, we need to iterate for all
	 * threads using threadgroup list in above while loop.
	 */
	list_for_each(list, &task->children) {

		child = list_entry(list, struct task_struct, sibling);

		/* Create at one lower hierarchy */
		ret = project4fs_create_hierarchy(sb, mydir, child, 1);
		if (ret)
			return ret;
	}
	return 0;
}

/* Initializes minimal amount of APIs needed for sb operations */
static struct super_operations project4_s_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= generic_show_options,
};

/**
 * @brief Initializes super block
 *
 * @param sb SuperBlock pointer
 * @param data Not Used
 * @param silent Not Used
 *
 * @return 0 for success, -ENOMEM on failure
 */
static int project4_fill_super (struct super_block *sb, void *data, int silent)
{
	struct inode *root;
	struct dentry *root_dentry;

	/* Initiliazes the super block */
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = PROJECT4_MAGIC;
	sb->s_op = &project4_s_ops;
	sb->s_time_gran		= 1;

	/*
	 * We need to conjure up an inode to represent the root directory
	 * of this filesystem.  Its operations all come from libfs, so we
	 * don't have to mess with actually *doing* things inside this
	 * directory.
	 */
	root = project4_make_inode (sb, S_IFDIR | 0755);
	if (!root) {
		printk(KERN_ERR "inode allocation failed\n");
		return -ENOMEM;
	}
	/* Register for inode operations, use libfs implementation */
	root->i_op = &simple_dir_inode_operations;

	/* Register for file operations, use libfs implementation */
	root->i_fop = &simple_dir_operations;

	/* Get a dentry to represent the directory in core. */
	root_dentry = d_make_root(root);
	if (! root_dentry) {
		/* Will try to free if usage count is 0 */
		printk(KERN_ERR "dentry allocation for root failed\n");
		iput(root);
		return -ENOMEM;
	}

	/* Store pointer for root dentry in sb */
	sb->s_root = root_dentry;

	/* Create the files we need. */
	return project4fs_create_hierarchy(sb, root_dentry, &init_task, 1);
}

/**
 * @brief Mounts the file system
 *
 * @return Return value of mount_nodev
 */
static struct dentry *project4_get_super(struct file_system_type *fst,
					 int flags,
					 const char *devname, void *data)
{
	return mount_nodev(fst, flags, data, project4_fill_super);
}

/**
 * @brief Handlers for this filesystem
 */
static struct file_system_type project4_type = {
	.owner		= THIS_MODULE,
	.name		= "project4",
	.mount		= project4_get_super,
	.kill_sb	= kill_litter_super,
};

/**
 * @brief Called during module init
 *
 * @return None
 */
static int __init project4_init(void)
{
	return register_filesystem(&project4_type);
}

/**
 * @brief Called during module unloading
 *
 * @return None
 */
static void __exit project4_exit(void)
{
	unregister_filesystem(&project4_type);
}

module_init(project4_init);
module_exit(project4_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abhishek Chauhan");
