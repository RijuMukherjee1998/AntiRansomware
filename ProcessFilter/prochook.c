#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <bcc/proto.h>

struct clone_data_t {
    u32 pid;
    u32 ppid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
};

struct open_data_t {
    u32 pid;
    u32 ppid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    u64 fd;
};

struct read_data_t {
    u32 pid;
    u32 ppid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    u64 fd;
};

struct write_data_t {
    u32 pid;
    u32 ppid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    u64 fd;
};

// struct filename_data_t{
//     char* filename[255];
// };



BPF_PERF_OUTPUT(clone_events);
BPF_PERF_OUTPUT(file_open_events);
BPF_PERF_OUTPUT(file_read_events);
BPF_PERF_OUTPUT(file_write_events);
// //internal hash to identify the file path from file descriptor id
// BPF_HASH(open_files, u64, struct filename_data_t);

// kprobe__(sys call name) -> it signifies the ebpf compiler that we are attaching a probe to a kernel sys call.
// so the hook name should start with kprobe__ then followed by the name of the sys call.
// int kprobe__sys_clone(struct pt_regs* ctx)
// {
//     struct data_t data = {}; 
//     struct task_struct *task;

//     task = (struct task_struct*) bpf_get_current_task();
//     data.uid = bpf_get_current_uid_gid();
//     data.pid = bpf_get_current_pid_tgid() >> 32;
//     data.ppid = task->real_parent->pid;
//     bpf_get_current_comm(&data.comm, sizeof(data.comm));
//     const char __user* filename = (const char*)PT_REGS_PARM1(ctx);
//     bpf_probe_read_user(&data.filename, sizeof(data.filename), filename);
//     clone_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }

int kprobe__sys_clone(void* ctx)
{
    struct clone_data_t data = {};
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid();
    data.timestamp = bpf_ktime_get_ns();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    clone_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int kprobe__do_sys_openat2(struct pt_regs* ctx, int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct open_data_t data = {};
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    u64 pid = bpf_get_current_pid_tgid();
    //u64 pid_fd = ((u64)bpf_get_current_pid_tgid() << 32) | (u32)PT_REGS_PARM1(ctx);  // PID + FD key
    data.pid = pid;
    //data.pid_fd = pid_fd;
    data.timestamp = bpf_ktime_get_ns();
    data.ppid = task->real_parent->tgid;
    data.fd = PT_REGS_PARM1(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.filename, sizeof(data.filename), filename);
    file_open_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, loff_t *pos) {
    struct read_data_t data = {};
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid();
    data.ppid = task->real_parent->tgid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Capture filename from the file struct
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), file->f_path.dentry->d_iname);

    file_read_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    struct write_data_t data = {};
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid();
    data.ppid = task->real_parent->tgid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Capture filename from the file struct
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), file->f_path.dentry->d_iname);

    file_write_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
