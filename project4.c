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
#define MAX_INFO 1024

/* Types of entry supported */
enum project4_entry_type {
	DIRECTORY = 0x0,
	SIGNAL_FILE,
	STATUS_FILE
};

unsigned long task_vsize(struct mm_struct *);

/* Types of tasks supported */
static char *task_type_array[] = {"KERNEL_THREAD", "USER_THREAD",
					"USER_PROCESS"};

/* Array of string to print signal name */
static char *signal_array[] = {"SIGHUP","SIGINT","SIGQUIT","SIGILL","SIGTRAP","SIGIOT",
	"SIGBUS","SIGFPE","SIGKILL","SIGUSR1","SIGSEGV","SIGUSR2","SIGPIPE","SIGALRM",
	"SIGTERM","SIGSTKFLT","SIGCHLD","SIGCONT","SIGSTOP","SIGTSTP","SIGTTIN",
	"SIGTTOU","SIGURG","SIGXCPU","SIGXFSZ","SIGVTALRM","SIGPROF","SIGWINCH",
	"SIGIO","SIGPWR"};

/* Types of states supported */
static const char * const task_state_array[] = {
	"R (running)",		/*   0 */
	"S (sleeping)",		/*   1 */
	"D (disk sleep)",	/*   2 */
	"T (stopped)",		/*   4 */
	"t (tracing stop)",	/*   8 */
	"X (dead)",		/*  16 */
	"Z (zombie)",		/*  32 */
};

static inline const char *get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->state | tsk->exit_state) & TASK_REPORT;

	BUILD_BUG_ON(1 + ilog2(TASK_REPORT) != ARRAY_SIZE(task_state_array)-1);

	return task_state_array[fls(state)];
}

/**
 * @brief Allocates the inode with given mode
 *
 * @param sb Super-Block for the FS
 * @param mode Mode for the inode
 *
 * @return Pointer to inode on success, NULL otherwise
 */
static struct inode *project4_allocate_inode(struct super_block *sb, int mode)
{
	struct inode *ret = new_inode(sb);

	if (likely(ret)) {
		ret->i_ino = get_next_ino();
		ret->i_mode = mode;
		ret->i_blocks = 0;
		ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
	}
	return ret;
}

/**
 * @brief Called when file is opened. Attaches the private data from inode.
 *
 * @param inode Inode Pointer for the file
 * @param filp File Pointer for the file
 *
 * @return 0 Always
 */
static int project4_open_file(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

/**
 * @brief Reads the status of task with pid same as file name
 *
 * @param filp File Pointer
 * @param buf User-space buffer
 * @param count Size of the buffer
 * @param offset Offset to read
 *
 * @return Number of bytes read
 */
static ssize_t project4_read_status_file(struct file *filp,
					 char __user *buf,
					 size_t count, loff_t *offset)
{
	/* NOTE: The below function may behave unappropriately if the process
	 * has been killed, followed by the task struct getting deallocated and
	 * reallocated for different task but same pid. :) Difficult scenario to
	 * create. This is my implementation limitations. The only other way was
	 * to copy entire data in mount time. I did not proceed that way due to
	 * inefficiency in implementation.
	 */
	char tmp[TASK_COMM_LEN];
	char buffer[MAX_INFO];
	struct task_struct *task;
	int type = 0;
	int length = 0;
	pid_t my_pid;
	pid_t my_tgid;
	pid_t arg_pid;
	struct mm_struct *mm;
	unsigned long hiwater_vm, text, data, lib, total_vm, stack_vm;
	int state, cpu;
	unsigned long long start_time;
	void *stack;

	if (unlikely(!buf || !filp || !offset)) {
		printk(KERN_ERR "Invalid Args for read status\n");
		return -EINVAL;
	}

	/* For checking if using correct task struct */
	my_pid = (pid_t)simple_strtol(filp->f_path.dentry->d_iname, NULL, 10);

	task = (struct task_struct *) filp->private_data;

	/* Null pointer for task struct */
	if (unlikely(!task)) {
		printk(KERN_ERR "Invalid Task struct found\n");
		return -EINVAL;
	}

	/* Lock for any access from task_struct */
	task_lock(task);
	arg_pid = task->pid;
	my_tgid = task->tgid;
	task_unlock(task);

	if (unlikely(my_pid != arg_pid)) {
		printk("Task struct has been allocated to new pid. Remount the filesystem\n");
		return -EINVAL;
	}

	mm = get_task_mm(task);

	length += snprintf(buffer + length, 1024, "########## Status ###########\n");

	/* Get the name of the task */
	get_task_comm(tmp, task);

	/* By default more tasks is in user-space hence likely */
	if (likely(mm)) {
		type = 1;

		/* Protect access of mm fields */
		task_lock(task);

		hiwater_vm = mm->total_vm > mm->hiwater_vm ?
						mm->total_vm : mm->hiwater_vm;
		text = (PAGE_ALIGN(mm->end_code) -
			(mm->start_code & PAGE_MASK)) >> 10;

		data = mm->total_vm - mm->shared_vm - mm->stack_vm;

		lib = (mm->exec_vm << (PAGE_SHIFT-10)) - text;

		total_vm = mm->total_vm;

		stack_vm = mm->stack_vm;

		task_unlock(task);
		/* Not sure if snprintf sleeps hence release the lock and used
		 * copied buffers.
		 */
		length += snprintf(buffer + length, 1024, "Virtual_Memory_Size:\t%lu kB\n",
				   (total_vm << (PAGE_SHIFT-10)));
		length += snprintf(buffer + length, 1024, "Virtual_Memory_Peak:\t%lu kB\n",
				   (hiwater_vm << (PAGE_SHIFT-10)));
		length += snprintf(buffer + length, 1024, "Text_VM:\t%lu kB\n",
				   (text << (PAGE_SHIFT-10)));
		length += snprintf(buffer + length, 1024, "Lib_VM:\t%lu kB\n",
				   (lib << (PAGE_SHIFT-10)));
		length += snprintf(buffer + length, 1024, "Data_VM:\t%lu kB\n",
				   (data << (PAGE_SHIFT-10)));
		length += snprintf(buffer + length, 1024, "Stack_VM:\t%lu kB\n",
				   (stack_vm << (PAGE_SHIFT-10)));
	}

	/* No statistics for likely and unlikely */
	if (type == 1 && my_pid == my_tgid) {
		type = 2;
	}

	/* Protect fields from task struct */
	task_lock(task);

	state = fls((task->state | task->exit_state) & TASK_REPORT);

	cpu = task_thread_info(task)->cpu;

	start_time = task->start_time;

	stack = task->stack;

	task_unlock(task);

	/* Not sure if snprintf sleeps hence release the lock and used
	 * copied buffers.
	 */
	length += snprintf(buffer + length, 1024, "State:\t%s\n",
			  task_state_array[state]);

	length += snprintf(buffer+length, 1024, "Type:\t%s\nCpu\t%d\n",
			  task_type_array[type],
			  cpu);

	/* Create the buffer to be copied in user space */
	length += snprintf(buffer+length, 1024, "Monotonic_Start_Time\t%lluns\nName:\t%s\nStack_Pointer:\t0x%p\n",
			  start_time,
			  tmp,
			  stack);

	length += snprintf(buffer + length, 1024, "#############################\n");

	if (likely(mm))
		mmput(mm);

	/* For partial read support */
	if (unlikely(length < count + *offset)) {
		count = length - *offset;
	}

	/* Perform copy to user */
	if (unlikely(copy_to_user(buf + *offset, buffer, count))) {
		printk("copying user space buffer failed\n");
		return -EFAULT;
	}

	/* Update the offset */
	*offset += count;

	return count;
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
static ssize_t project4_write_status_file(struct file *filp, const char *buf,
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
static ssize_t project4_read_signal_file(struct file *filp, char *buf,
				  size_t count, loff_t *offset)
{
	/* Reading Signal File is not supported */
	return -EINVAL;
}

/**
 * @brief Delivers signal to the pid with file name
 *
 * @param filp File pointer for the file
 * @param buf buffer pointer for the file
 * @param count Count of bytes to be copied
 * @param offset Offset where we need to write
 *
 * @return Number of bytes written
 */
static ssize_t project4_write_signal_file(struct file *filp, const char *buf,
				   size_t count, loff_t *offset)
{
	struct task_struct *task;
	char tmp[TMPSIZE];
	struct siginfo info;
	int sig_num;
	int ret;

	if (unlikely(!buf || !filp || !offset)) {
		printk(KERN_ERR "Invalid Args for write signal\n");
		return -EINVAL;
	}

	/* Partial write not supported as the requirement is very small */
	if (unlikely(*offset != 0)) {
		return -EINVAL;
	}

	task = (struct task_struct *) filp->private_data;

	/* Null pointer for task struct */
	if (unlikely(!task)) {
		printk(KERN_ERR "Invalid Task struct found\n");
		return -EINVAL;
	}

	memset(tmp, 0, TMPSIZE);

	/* Copy the signal from user */
	if (unlikely(copy_from_user(tmp, buf, count))) {
		printk("copying user space buffer failed\n");
		return -EINVAL;
	}

	/* Extract the signal number */
	sig_num = (int)simple_strtol(tmp, NULL, 10);

	/*Error check for signal number range */
	if(unlikely(sig_num <= 0 || sig_num > 30)) {
		printk("Invalid signal number passed. Allowed range [1-30]\n");
		return -EINVAL;
	}

	info.si_signo = sig_num;
	info.si_code = SI_KERNEL;
	info.si_errno = 0;
	info.si_pid = 0;
	info.si_uid = 0;

	/* Send the signal to the desired process */
	ret = send_sig_info(sig_num, &info, task);
	if (unlikely(ret < 0)) {
		printk(KERN_ERR "Signal %s<%d> failed PID<%d> TID<%d>\n",
			signal_array[sig_num-1],sig_num,task->tgid, task->pid);
		return ret;
	}
	printk(KERN_INFO "Signal %s<%d> delivered PID<%d> TID<%d>\n",
	       signal_array[sig_num-1],sig_num,task->tgid, task->pid);

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
static struct file_operations project4_signal_file_ops = {
	.open	= project4_open_file,
	.read	= project4_read_signal_file,
	.write  = project4_write_signal_file,
	.release  = project4_release
};

/**
 * @brief File Operations for the Status files
 */
static struct file_operations project4_status_file_ops = {
	.open	= project4_open_file,
	.read	= project4_read_status_file,
	.write  = project4_write_status_file,
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
	if (unlikely(!dentry)) {
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
	inode = project4_allocate_inode(sb, mode);
	if (unlikely(!inode)) {
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
			inode->i_fop = &project4_signal_file_ops;
			inode->i_private = priv_data;
			break;
		case STATUS_FILE:
			inode->i_fop = &project4_status_file_ops;
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
	if (unlikely(!task))
		return 0;

	/* Create String from pid */
	snprintf(buffer, 20, "%d",task->pid);

	/* Create directory with pid */
	mydir = project4_create_entry(sb, root, buffer, DIRECTORY, NULL);

	if (unlikely(!mydir)) {
		printk(KERN_ERR
		       "failed to create directory for %s\n", buffer);
		return -ENOMEM;
	}

	/* Create Signal file inside the pid directory */
	myfile =project4_create_entry(sb, mydir, "signal", SIGNAL_FILE, task);
	if (unlikely(!myfile)) {
		printk(KERN_ERR
		       "failed to create signal file \n");
		return -ENOMEM;
	}

	/* Create String from status file */
	snprintf(buffer, 20, "%d.status",task->pid);

	/* Create Status file inside the pid directory */
	myfile = project4_create_entry(sb, mydir, buffer, STATUS_FILE, task);
	if (unlikely(!myfile)) {
		printk(KERN_ERR
		       "failed to create status file  %s\n", buffer);
		return -ENOMEM;
	}

	/* Only the first process will create the directory for all threads in
	 * the thread group. This is requried to avoid multiple calls to same
	 * thread as the thread-group list is double link list without any start
	 * and end
	 */
	if (unlikely(create_threads)) {
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
		if (unlikely(ret))
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
	root = project4_allocate_inode (sb, S_IFDIR | 0755);
	if (unlikely(!root)) {
		printk(KERN_ERR "inode allocation failed\n");
		return -ENOMEM;
	}
	/* Register for inode operations, use libfs implementation */
	root->i_op = &simple_dir_inode_operations;

	/* Register for file operations, use libfs implementation */
	root->i_fop = &simple_dir_operations;

	/* Get a dentry to represent the directory in core. */
	root_dentry = d_make_root(root);
	if (unlikely(!root_dentry)) {
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
