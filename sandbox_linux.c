#define _GNU_SOURCE

#include "sandbox.h"
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <asm-generic/resource.h>
#include <seccomp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>


const char *safe_paths[] = {
	"/lib/",
	"/lib32/",
	"/lib64/",
	"/usr/lib/",
	"/usr/lib32/",
	"/usr/lib64/",
	"/usr/include/",
	"/usr/libexec/",
	"/usr/local/lib/",
	"/usr/local/lib32/",
	"/usr/local/lib64/",
	"/usr/local/include/",
	"/usr/local/libexec/",
	"/bin/",
	"/usr/bin/",
	"/usr/local/bin/",
	"/usr/share/",
	"/usr/local/share/",
	"/dev/urandom",
	"/dev/zero",
	"/dev/null",
	"/sbin",
	"/usr/sbin",
	"/usr/local/sbin",
	"/proc/self/",
	"/etc/ld.so.cache",
	"/tmp",
	"/usr/pyvenv.cfg",
	NULL
};

char * normalize_path(const char * src, size_t src_len) {
	char * res;
	size_t res_len;

	const char * ptr = src;
	const char * end = &src[src_len];
	const char * next;

	if (src_len == 0 || src[0] != '/') {
		char pwd[PATH_MAX];
		size_t pwd_len;

		if (getcwd(pwd, sizeof(pwd)) == NULL) {
			return NULL;
		}

		pwd_len = strlen(pwd);
		res = malloc(pwd_len + 1 + src_len + 1);
		memcpy(res, pwd, pwd_len);
		res_len = pwd_len;
	} else {
		res = malloc((src_len > 0 ? src_len : 1) + 1);
		res_len = 0;
	}

	for (ptr = src; ptr < end; ptr = next + 1) {
		size_t len;
		next = memchr(ptr, '/', end-ptr);
		if (next == NULL) {
			next = end;
		}
		len = next - ptr;
		switch(len) {
		case 2:
			if (ptr[0] == '.' && ptr[1] == '.') {
				const char * slash = memrchr(res, '/', res_len);
				if (slash != NULL) {
					res_len = slash - res;
				}
				continue;
			}
			break;
		case 1:
			if (ptr[0] == '.') {
				continue;
			}
			break;
		case 0:
			continue;
		}
		res[res_len++] = '/';
		memcpy(&res[res_len], ptr, len);
		res_len += len;
	}

	if (res_len == 0) {
		res[res_len++] = '/';
	}
	res[res_len] = '\0';
	return res;
}

bool is_path_safe_impl(const char *path) {
	const char *s;
	int i;

	if (strstr(path, ".."))
		return false;
	for (i = 0; safe_paths[i] && strncmp(path, safe_paths[i], strlen(safe_paths[i])); ++i);
	if (safe_paths[i]) {
		return true;
	}
	int len = strlen(path);
	for (i = 0; safe_paths[i]; ++i) {
		if (safe_paths[i][strlen(safe_paths[i] - 1)] == '/')
			if (len == strlen(safe_paths[i]) - 1)
				if (!strncmp(path, safe_paths[i], strlen(safe_paths[i]) - 1))
					return true;
	}

	s = path;
	while (s[0] == '.' && s[1] == '/') s += 2;
	for (; *s && *s != '/'; s++);
	if (*s == '/') return false;
	return true;
}


bool is_path_safe(const char *path) {
	return is_path_safe_impl(path) || is_path_safe_impl(normalize_path(path, strlen(path)));
}

#define MAX_PATH_PREFIX 256


const char *syscalls_deny[] = {
	"bdflush",
	"chdir",
	"chroot",
	"epoll_create1",
	"epoll_ctl",
	"epoll_pwait",
	"epoll_wait",
	"eventfd2",
	"faccessat",
	"fallocate",
	"fanotify_init",
	"fanotify_mark",
	"fchdir",
	//"fcntl",
	//"fcntl64",
	"fdatasync",
	"flock",
	"fstatat64",
	"fstatfs",
	"fstatfs64",
	"fsync",
	"ftruncate",
	"ftruncate64",
	"getcwd",
	"get_mempolicy",
	//"getrandom",
	"getrusage",
	"inotify_add_watch",
	"inotify_init1",
	"inotify_rm_watch",
	//"ioctl",
	"io_cancel",
	"io_destroy",
	"io_getevents",
	"ioperm",
	"iopl",
	"io_setup",
	"io_submit",
	"linkat",
	"madvise",
	"mbind",
	"memfd_create",
	"migrate_pages",
	"mincore",
	"mlock",
	"mlock2",
	"mlockall",
	"mmap_pgoff",
	"move_pages",
	"msync",
	"munlock",
	"munlockall",
	"newfstatat",
	"nice",
	"personality",
	"ppoll",
	"pread64",
	"preadv",
	"preadv2",
	"process_vm_readv",
	"process_vm_writev",
	"pwrite64",
	"pwritev",
	"pwritev2",
	"readahead",
	"readlinkat",
	"renameat2",
	"rmdir",
	"rt_sigprocmask",
	"seccomp",
	"set_mempolicy",
	"sigaltstack",
	"signalfd4",
	"sigprocmask",
	"splice",
	"ssetmask",
	"statfs",
	"statfs64",
	"symlinkat",
	"sync",
	"sync_file_range",
	"syncfs",
	"sysinfo",
	"syslog",
	"tee",
	"timerfd_create",
	"timerfd_gettime",
	"timerfd_settime",
	"truncate",
	"truncate64",
	"umask",
	"unlink",
	"unlinkat",
	"uselib",
	"ustat",
	"vhangup",
	"vmsplice",
	"writev",
	NULL
};

const char *syscalls_fs[] = {
	"lstat64",
	"lstat",
	"newlstat",
	"newstat",
	"open",
	"stat64",
	"stat",
	NULL
};

const char *syscalls_once[] = {
	"execve",
	NULL
};

const char *syscalls_sec[] = {
	"accept4",
	"acct",
	"add_key",
	"adjtimex",
	"bind",
	"bpf",
	"capset",
	"clock_adjtime",
	"clock_settime",
	"connect",
	"delete_module",
	"fchmodat",
	"fchmod",
	"fchownat",
	"fchown",
	"fgetxattr",
	"finit_module",
	"flistxattr",
	"fork",
	"fremovexattr",
	"fsetxattr",
	"futimesat",
	"getitimer",
	"getpeername",
	"getsockname",
	"getsockopt",
	"getxattr",
	"init_module",
	"ioprio_set",
	"ipc",
	"kcmp",
	"kexec_load",
	"keyctl",
	"kill",
	"lgetxattr",
	"listen",
	"listxattr",
	"llistxattr",
	"lookup_dcookie",
	"lremovexattr",
	"lsetxattr",
	"membarrier",
	"mkdirat",
	"mknodat",
	"modify_ldt",
	"mount",
	"mq_getsetattr",
	"mq_notify",
	"mq_open",
	"mq_timedreceive",
	"mq_timedsend",
	"mq_unlink",
	"msgctl",
	"msgget",
	"msgrcv",
	"msgsnd",
	"name_to_handle_at",
	"openat",
	"open_by_handle_at",
	"perf_event_open",
	"pipe2",
	"pivot_root",
	"pkey_alloc",
	"pkey_free",
	"prctl",
	"prlimit64",
	"ptrace",
	"quotactl",
	"reboot",
	"recvfrom",
	"recvmmsg",
	"recvmsg",
	"recv",
	"remap_file_pages",
	"removexattr",
	"request_key",
	"sched_setaffinity",
	"sched_setattr",
	"sched_setparam",
	"sched_setscheduler",
	"semctl",
	"semget",
	"semtimedop",
	"sendmmsg",
	"sendmsg",
	"sendto",
	"setdomainname",
	"setfsgid",
	"setfsuid",
	"setgid",
	"setgroups16",
	"setgroups",
	"sethostname",
	"setitimer",
	"setns",
	"setpgid",
	"setpriority",
	"setregid",
	"setresgid",
	"setresuid",
	"setreuid",
	"setrlimit",
	"setsid",
	"setsockopt",
	"settimeofday",
	"setuid",
	"setxattr",
	"shmat",
	"shmctl",
	"shmdt",
	"shmget",
	"shutdown",
	"socketcall",
	"socketpair",
	"socket",
	"stime",
	"swapoff",
	"swapon",
	"sysctl",
	"sysfs",
	//"tgkill",
	"timer_create",
	"timer_settime",
	"times",
	"tkill",
	"umount",
	"unshare",
	"userfaultfd",
	"utimensat",
	"utime",
	"vfork",
	"vm86old",
	"vm86",
	NULL
};


void set_memory_limit(long bytes)
{
	struct rlimit rmemlimit; 
	rmemlimit.rlim_cur = bytes;
	rmemlimit.rlim_max = bytes;
	setrlimit(RLIMIT_AS, &rmemlimit);
	setrlimit(RLIMIT_STACK, &rmemlimit);
}

void set_cpu_limit(long msec)
{
	long sec = (msec + 999) / 1000; // msec -> sec, rounded up
	struct rlimit rtimelimit; 
	rtimelimit.rlim_cur = sec;
	rtimelimit.rlim_max = sec;
	setrlimit(RLIMIT_CPU, &rtimelimit);
}

#define PTRACE_DENY 0xf2
#define PTRACE_FS   0xf3
#define PTRACE_SEC  0xf4
#define PTRACE_ONCE 0xf5

void blacklist(scmp_filter_ctx ctx, const char **group, unsigned long action) {
	for (const char **c = group; *c; ++c) {
		int i = seccomp_syscall_resolve_name(*c);
		if (i != __NR_SCMP_ERROR) {
			seccomp_rule_add(ctx, action, i, 0);
		}
	}
}

#define SYSCALL_LEN 1024

char *read_all(int fd) {
	char *res = malloc(1);
	res[0] = (char)0;

	char buf[1024];
	int z;
	int len = 1;
	while ((z = read(fd, buf, sizeof(buf))) != 0)
	{
		len += z;
		char *tmp = realloc(res, len);
		if (tmp) {
			res = tmp;
		} else {
			close(fd);
			return NULL;
		}
		strncat(res, buf, z);
	} 
	close(fd);
	return res;
}

sandbox_result_t sandbox_run(const sandbox_config_t *cfg) {
	sandbox_result_t result;
	result.verdict = ER_FAIL;
	result.exit_code = 0;
	result.cpu_time = 0;
	result.mem_usage = 0;
	int action[SYSCALL_LEN];
	memset(action, 0, SYSCALL_LEN * sizeof(int));

	for (const char **c = syscalls_deny; *c; ++c) {
		int i = seccomp_syscall_resolve_name(*c);
		if (i >= 0) {
			action[i] = PTRACE_DENY;
		}
	}

	for (const char **c = syscalls_fs; *c; ++c) {
		int i = seccomp_syscall_resolve_name(*c);
		if (i >= 0) {
			action[i] = PTRACE_FS;
		}
	}

	for (const char **c = syscalls_once; *c; ++c) {
		int i = seccomp_syscall_resolve_name(*c);
		if (i >= 0) {
			action[i] = PTRACE_ONCE;
		}
	}

	for (const char **c = syscalls_sec; *c; ++c) {
		int i = seccomp_syscall_resolve_name(*c);
		if (i >= 0) {
			action[i] = PTRACE_SEC;
		}
	}

	int stdin_pipe[2];
	int stdout_pipe[2];
	int stderr_pipe[2];

	pipe(stdin_pipe);
	pipe(stdout_pipe);
	pipe(stderr_pipe);

	write(stdin_pipe[1], cfg->s_stdin, strlen(cfg->s_stdin) + 1);
	close(stdin_pipe[1]);

	int pid = fork();
	if (pid == 0) {
		if (cfg->time_limit > 0) {
			set_cpu_limit(cfg->time_limit);
		}

		if (cfg->mem_limit > 0) {
			set_memory_limit(cfg->mem_limit);
		}
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);

		blacklist(ctx, syscalls_deny, SCMP_ACT_ERRNO(EPERM));
		blacklist(ctx, syscalls_sec, SCMP_ACT_ERRNO(EPERM));


		if (cfg->debug) {
			fprintf(stderr, "(target) starting %s\n", cfg->path);
		}

		close(stdout_pipe[0]);
		close(stderr_pipe[0]);

		dup2(stdin_pipe[0], 0);
		dup2(stdout_pipe[1], 1);
		//dup2(stderr_pipe[1], 2);
	
		seccomp_load(ctx);

		if (cfg->use_env) {
			execvpe(cfg->path, cfg->args, cfg->env);
		} else {
			execvp(cfg->path, cfg->args);
		}
		if (cfg->debug) {
			fprintf(stderr, "(target) unable to execve\n");
		}
		exit(254); // TODO: we need to somehow return ER_FAIL
	} else if (pid < 0) {
		close(stdin_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[1]);
		close(stdout_pipe[1]);
		close(stderr_pipe[1]);
		if (cfg->debug) {
			fprintf(stderr, "(sandbox) unable to fork\n");
			fprintf(stderr, "(sandbox) verdict: fail\n");
		}
		return result;
	} else {
		ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL);
		close(stdin_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[1]);
		int wtpid = fork();
		if (wtpid == 0) {
			usleep(cfg->wall_time_limit * 1000);
			exit(0);
		}
		if (wtpid < 0) {
			close(stdout_pipe[0]);
			close(stderr_pipe[0]);
			if (cfg->debug) {
				fprintf(stderr, "(sandbox) unable to fork\n");
				fprintf(stderr, "(sandbox) verdict: fail\n");
			}
			return result;
		}

		int pstatus;
		bool ex = false;
		bool insyscall = false;
		if (cfg->debug) {
			fprintf(stderr, "(sandbox) waiting for events\n");
		}
		int ppid = wait(&pstatus);
		result.verdict = ER_OK;
		while (1) {
			if (ppid == wtpid) {
				kill(pid, SIGKILL);
				if (cfg->debug) {
					fprintf(stderr, "(sandbox) wall time limit\n");
				}
				result.verdict = ER_WT;
				goto ret;
			}

			if (WSTOPSIG(pstatus) == SIGTRAP) {
				int syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, 0);
				insyscall = !insyscall;
				unsigned long data = action[syscall];

				if (insyscall) {
					if (data == PTRACE_SEC) {
						if (cfg->debug) {
							fprintf(stderr, "(sandbox) security violation: forbidden syscall\n");
						}
						result.verdict = ER_SE;
					}

					if (data == PTRACE_FS) {						
						unsigned long arg1 = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RDI, 0);
						char buf[PATH_MAX];
						unsigned long idx;
						memset(buf, 0, PATH_MAX);
						for (idx = 0; idx < PATH_MAX - sizeof(long);) {
							unsigned long x = ptrace(PTRACE_PEEKDATA, pid, arg1 + idx);
							for (int i = 0; i < sizeof(long); ++i) {
								unsigned char c = x & 0xff;
								buf[idx] = c;
								idx++;
								x >>= 8;
								if (c == 0) goto q;
							}
						}
						buf[PATH_MAX - 1] = (char)0;
						q:;
						if (!is_path_safe(buf)) {
							if (cfg->debug) {
								fprintf(stderr, "(sandbox) security violation: forbidden path %s\n", buf);
							}
							result.verdict = ER_SE;
						}
					}

					if (data == PTRACE_ONCE) {
						if (ex) {
							if (cfg->debug) {
								fprintf(stderr, "(sandbox) security violation: execve called\n");
							}
							result.verdict = ER_SE;
						} else {
							ex = true;
						}
					}
				}

				if (result.verdict != ER_OK) {
					kill(pid, SIGKILL);
					kill(wtpid, SIGKILL);
					result.exit_code = syscall;
					goto ret;
				}

				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
			} else {
				kill(wtpid, SIGKILL);

				if (WIFSIGNALED(pstatus)) {
					int sig = WTERMSIG(pstatus);
					if (sig == SIGXCPU || sig == SIGKILL) {
						if (cfg->debug) {
							fprintf(stderr, "(sandbox) time limit: SIGXCPU or SIGKILL\n");
						}
						result.verdict = ER_TL;
						goto ret;
					}
				}

				result.exit_code = WEXITSTATUS(pstatus);

				if (result.exit_code) {
					if (cfg->debug) {
						fprintf(stderr, "(sandbox) runtime error: exit_code is not null\n");
					}
					result.verdict = ER_RT;
				} else {
					if (cfg->debug) {
						fprintf(stderr, "(sandbox) ok\n");
					}
					result.verdict = ER_OK;
				}

				goto ret;
			}

			ppid = wait(&pstatus);
		}
	}

	ret:;
	struct rusage usage;
	getrusage(RUSAGE_CHILDREN, &usage);
	result.cpu_time = usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000;
	result.mem_usage = usage.ru_maxrss * 1024;
	if (cfg->debug) {
		fprintf(stderr, "(sandbox) process finished. cpu_time = %ld ms, mem_usage = %ld bytes\n", result.cpu_time, result.mem_usage);
	}

	if (result.cpu_time > cfg->time_limit && cfg->time_limit > 0) {
		result.verdict = ER_TL;
	}

	if (result.mem_usage > cfg->mem_limit && cfg->mem_limit > 0) {
		result.verdict = ER_ML;
	}

	result.s_stdout = read_all(stdout_pipe[0]);
	if (!result.s_stdout) {
		fprintf(stderr, "(sandbox) fail: error when reading from stdout pipe\n");
		result.verdict = ER_FAIL;
	}

	result.s_stderr = read_all(stderr_pipe[0]);
	if (!result.s_stderr) {
		fprintf(stderr, "(sandbox) fail: error when reading from stderr pipe\n");
		result.verdict = ER_FAIL;
	}

	if (cfg->debug) {
		switch (result.verdict) {
			case ER_OK: fprintf(stderr, "(sandbox) verdict: ok.\n"); break;
			case ER_TL: fprintf(stderr, "(sandbox) verdict: time limit exceeded. TL = %ld ms\n", cfg->time_limit); break;
			case ER_ML: fprintf(stderr, "(sandbox) verdict: memory limit exeeded. ML = %ld bytes\n", cfg->mem_limit); break;
			case ER_RT: fprintf(stderr, "(sandbox) verdict: runtime error. EXITCODE = %d\n", result.exit_code); break;
			case ER_WT: fprintf(stderr, "(sandbox) verdict: wall time limit exceeded. WT = %ld ms\n", cfg->wall_time_limit); break;
			case ER_SE: fprintf(stderr, "(sandbox) verdict: security violation. SYSCALL = %d\n", result.exit_code); break;
			case ER_FAIL: fprintf(stderr, "(sandbox) verdict: fail\n"); break;
		}
	}

	fprintf(stderr, "(sandbox) stdout:\n%s\n", result.s_stdout);
	fprintf(stderr, "(sandbox) stderr:\n%s\n", result.s_stderr);

	return result;
}
