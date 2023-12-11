#include "abi-bits/fcntl.h"
#include "abi-bits/gid_t.h"
#include "abi-bits/seek-whence.h"
#include "abi-bits/uid_t.h"
#include "abi-bits/vm-flags.h"
#include "mlibc/ansi-sysdeps.hpp"
#include "mlibc/debug.hpp"
#include "mlibc/fsfd_target.hpp"
#include "mlibc/posix-sysdeps.hpp"
#include "mos/filesystem/fs_types.h"
#include "mos/io/io_types.h"
#include "mos/mm/mm_types.h"
#include "mos/platform_syscall.h"
#include "mos/tasks/signal_types.h"
#include "mos/types.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <mlibc/all-sysdeps.hpp>
#include <mos/syscall/usermode.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <unistd.h>

#if defined(__riscv) && __riscv_xlen == 64
#include "mlibc/tcb.hpp"
#endif

static constexpr inline bool no_log = false;

#pragma GCC diagnostic ignored "-Wunused-parameter"

#define VERIFY_RET(ret)                                                                            \
	do {                                                                                           \
		if (IS_ERR_VALUE(ret))                                                                     \
			return -ret;                                                                           \
	} while (0)

#define DEFINE_ENUM_FLAG_OPERATORS(ENUMTYPE)                                                       \
	inline ENUMTYPE operator|(ENUMTYPE a, ENUMTYPE b) {                                            \
		return static_cast<ENUMTYPE>(static_cast<int>(a) | static_cast<int>(b));                   \
	}                                                                                              \
	inline ENUMTYPE &operator|=(ENUMTYPE &a, ENUMTYPE b) { return a = a | b; }

DEFINE_ENUM_FLAG_OPERATORS(mem_perm_t);
DEFINE_ENUM_FLAG_OPERATORS(open_flags);
DEFINE_ENUM_FLAG_OPERATORS(mmap_flags_t);
DEFINE_ENUM_FLAG_OPERATORS(FDFlag);

static mmap_flags_t get_mmap_flags(int flags) {
	mmap_flags_t mos_flags = (mmap_flags_t)0;
	if (flags & MAP_PRIVATE)
		mos_flags |= MMAP_PRIVATE;
	if (flags & MAP_SHARED)
		mos_flags |= MMAP_SHARED;
	if (flags & MAP_FIXED)
		mos_flags |= MMAP_EXACT;
	return mos_flags;
}

static mem_perm_t get_mmap_prot(int prot) {
	mem_perm_t mos_prot = (mem_perm_t)0;
	if (prot & PROT_READ)
		mos_prot |= MEM_PERM_READ;
	if (prot & PROT_WRITE)
		mos_prot |= MEM_PERM_WRITE;
	if (prot & PROT_EXEC)
		mos_prot |= MEM_PERM_EXEC;
	return mos_prot;
}

static open_flags get_open_flags(int flags, int mode) {
	open_flags mos_flags = (open_flags)0;

	const auto accmode = flags & O_ACCMODE;

	if (accmode == O_RDONLY)
		mos_flags |= OPEN_READ;
	else if (accmode == O_WRONLY)
		mos_flags |= OPEN_WRITE;
	else if (accmode == O_RDWR)
		mos_flags |= OPEN_READ | OPEN_WRITE;
	else if (accmode == O_EXEC)
		mos_flags |= OPEN_EXECUTE;
	else if (accmode == O_SEARCH)
		mlibc::infoLogger() << "O_SEARCH is not supported" << frg::endlog;

	if (mode & O_APPEND)
		mos_flags |= OPEN_APPEND;

	if (mode & O_CLOEXEC)
		mlibc::infoLogger() << "O_CLOEXEC is not supported" << frg::endlog;

	if (flags & O_DIRECTORY)
		mos_flags |= OPEN_DIR;

	if (flags & O_EXCL)
		mos_flags |= OPEN_EXCLUSIVE;

	if (flags & O_NOFOLLOW)
		mos_flags |= OPEN_NO_FOLLOW;

	if (flags & O_CREAT)
		mos_flags |= OPEN_CREATE;

	if (flags & O_TRUNC)
		mos_flags |= OPEN_TRUNCATE;
	return mos_flags;
}

namespace mlibc {
#define FD_in 0
#define FD_out 1
#define FD_err 2

void sys_libc_log(const char *message) {
	if (no_log)
		return; // don't log anything if we are showing off the OS

	const size_t len = strlen(message);
	syscall_io_write(FD_err, message, len);
	syscall_io_write(FD_err, "\n", 1);
}

void sys_libc_panic() {
	const auto msg = "\033[1;31mPANIC\033[0m: libc has encountered a fatal error.\n";
	syscall_io_write(FD_err, msg, strlen(msg));
	syscall_exit(-1);
}

int sys_tcb_set(void *pointer) {
#if defined(__x86_64__)
	syscall_arch_syscall(X86_SYSCALL_SET_FS_BASE, (ptr_t)pointer, 0, 0, 0);
#elif defined(__riscv) && __riscv_xlen == 64
	// RISC-V TCB is below the thread pointer
	syscall_arch_syscall(RISCV64_SYSCALL_SET_TP, (ptr_t)pointer + sizeof(Tcb), 0, 0, 0);
#else
#error "Unsupported architecture"
#endif
	return 0;
}

int sys_futex_tid() { return syscall_get_tid(); }

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
	long ret = syscall_futex_wait(pointer, expected);
	VERIFY_RET(ret);

	return 0;
}

int sys_futex_wake(int *pointer) {
	long ret = syscall_futex_wake(pointer, INT_MAX);
	VERIFY_RET(ret);
	return 0;
}

int sys_anon_allocate(size_t size, void **pointer) {
	long ptr = (long)syscall_mmap_anonymous(0, size, MEM_PERM_READ | MEM_PERM_WRITE, MMAP_PRIVATE);
	VERIFY_RET(ptr);
	*pointer = (void *)ptr;
	return 0;
}

int sys_anon_free(void *pointer, size_t size) { return !syscall_munmap(pointer, size); }

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
	long ret = syscall_vfs_openat(AT_FDCWD, pathname, get_open_flags(flags, mode));
	VERIFY_RET(ret);
	*fd = ret;
	return 0;
}

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	long ret = syscall_vfs_openat(dirfd, path, get_open_flags(flags, mode));
	VERIFY_RET(ret);
	*fd = ret;
	return 0;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	long ret = syscall_io_read(fd, buf, count);
	VERIFY_RET(ret);

	*bytes_read = ret;
	return 0;
}

int sys_readv(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_read) {
	long ret = syscall_io_readv(fd, iovs, iovc);
	VERIFY_RET(ret);

	*bytes_read = ret;
	return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	if (fd == FD_in || fd == FD_out || fd == FD_err)
		return ESPIPE;

	if (whence == SEEK_CUR)
		*new_offset = syscall_io_seek(fd, offset, IO_SEEK_CURRENT);
	else if (whence == SEEK_SET)
		*new_offset = syscall_io_seek(fd, offset, IO_SEEK_SET);
	else if (whence == SEEK_END)
		*new_offset = syscall_io_seek(fd, offset, IO_SEEK_END);
	else if (whence == SEEK_DATA)
		*new_offset = syscall_io_seek(fd, offset, IO_SEEK_DATA);
	else if (whence == SEEK_HOLE)
		*new_offset = syscall_io_seek(fd, offset, IO_SEEK_HOLE);
	else {
		mlibc::infoLogger() << "sys_seek: Invalid whence: " << whence << frg::endlog;
		return 1;
	}
	return 0;
}

int sys_close(int fd) { return !syscall_io_close(fd); }

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	file_stat_t mos_stat;
	if (fsfdt == fsfd_target::fd) {
		long ret = syscall_vfs_fstatat(fd, NULL, &mos_stat, fstatat_flags::FSTATAT_FILE);
		VERIFY_RET(ret);
	} else if (fsfdt == fsfd_target::path) {
		long ret = syscall_vfs_fstatat(AT_FDCWD, path, &mos_stat, fstatat_flags::FSTATAT_NONE);
		VERIFY_RET(ret);
	} else {
		return EINVAL;
	}

	const auto mode = [&]() {
		mode_t mode = 0;
		if (mos_stat.type == FILE_TYPE_REGULAR)
			mode |= S_IFREG;
		else if (mos_stat.type == FILE_TYPE_DIRECTORY)
			mode |= S_IFDIR;
		else if (mos_stat.type == FILE_TYPE_SYMLINK)
			mode |= S_IFLNK;
		else
			mode |= S_IFSOCK;

		if (mos_stat.perm & (PERM_OWNER & PERM_READ))
			mode |= S_IRUSR;
		if (mos_stat.perm & (PERM_OWNER & PERM_WRITE))
			mode |= S_IWUSR;
		if (mos_stat.perm & (PERM_OWNER & PERM_EXEC))
			mode |= S_IXUSR;
		if (mos_stat.perm & (PERM_GROUP & PERM_READ))
			mode |= S_IRGRP;
		if (mos_stat.perm & (PERM_GROUP & PERM_WRITE))
			mode |= S_IWGRP;
		if (mos_stat.perm & (PERM_GROUP & PERM_EXEC))
			mode |= S_IXGRP;
		if (mos_stat.perm & (PERM_OTHER & PERM_READ))
			mode |= S_IROTH;
		if (mos_stat.perm & (PERM_OTHER & PERM_WRITE))
			mode |= S_IWOTH;
		if (mos_stat.perm & (PERM_OTHER & PERM_EXEC))
			mode |= S_IXOTH;
		if (mos_stat.sgid)
			mode |= S_ISGID;
		if (mos_stat.suid)
			mode |= S_ISUID;
		if (mos_stat.sticky)
			mode |= S_ISVTX;
		return mode;
	}();

	statbuf->st_dev = 0;
	statbuf->st_ino = mos_stat.ino;
	statbuf->st_mode = mode;
	statbuf->st_nlink = mos_stat.nlinks;
	statbuf->st_uid = mos_stat.uid;
	statbuf->st_gid = mos_stat.gid;
	statbuf->st_rdev = 0;
	statbuf->st_size = mos_stat.size;
	statbuf->st_blksize = 0;
	statbuf->st_blocks = 0;
	statbuf->st_atim.tv_sec = mos_stat.accessed;
	statbuf->st_atim.tv_nsec = 0;
	statbuf->st_mtim.tv_sec = mos_stat.modified;
	statbuf->st_mtim.tv_nsec = 0;
	statbuf->st_ctim.tv_sec = mos_stat.created;
	statbuf->st_ctim.tv_nsec = 0;

	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	const auto mmap_prot = get_mmap_prot(prot);
	const auto mmap_flags = get_mmap_flags(flags);

	if (flags & MAP_ANONYMOUS) {
		void *ptr = syscall_mmap_anonymous((ptr_t)hint, size, mmap_prot, mmap_flags);
		if (window)
			*window = ptr;
		return ptr ? 0 : -1;
	} else {
		void *ptr = syscall_mmap_file((ptr_t)hint, size, mmap_prot, mmap_flags, fd, offset);
		if (window)
			*window = ptr;
		return ptr ? 0 : -1;
	}
	return 0;
}

int sys_vm_unmap(void *pointer, size_t size) { return !syscall_munmap(pointer, size); }

int sys_vm_protect(void *pointer, size_t size, int prot) {
	mem_perm_t mos_prot = get_mmap_prot(prot);
	return !syscall_vm_protect(pointer, size, mos_prot);
}

void sys_exit(int status) { syscall_exit(status); }

void sys_thread_exit() { syscall_thread_exit(); }

int sys_flock(int fd, int options) { return 0; }

int sys_open_dir(const char *path, int *handle) {
	const auto ret = syscall_vfs_openat(AT_FDCWD, path, OPEN_DIR);
	VERIFY_RET((long)ret);
	*handle = ret;
	return 0;
}

int sys_chdir(const char *path) {
	long ret = syscall_vfs_chdirat(AT_FDCWD, path);
	VERIFY_RET(ret);
	return 0;
}

int sys_getcwd(char *buffer, size_t size) {
	syscall_vfs_getcwd(buffer, size);
	return 0;
}

int sys_mkdir(const char *path, mode_t mode) {
	long ret = syscall_vfs_mkdir(path);
	VERIFY_RET(ret);
	return 0;
}

int sys_link(const char *old_path, const char *new_path) {
	long ret = syscall_vfs_symlink(old_path, new_path);
	VERIFY_RET(ret);
	return 0;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	*bytes_written = syscall_io_write(fd, buf, count);
	return 0;
}

int sys_pread(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	long ret = syscall_io_pread(fd, buf, n, off);
	VERIFY_RET(ret);

	*bytes_read = ret;
	return 0;
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	struct timespec ts;
	long ret = syscall_clock_gettimeofday(&ts);
	VERIFY_RET(ret);

	*secs = ts.tv_sec;
	*nanos = ts.tv_nsec;
	return 0;
}

int sys_clock_getres(int clock, time_t *secs, long *nanos) {
	mlibc::infoLogger() << "stub sys_clock_getres: " << clock << frg::endlog;
	return 0;
}

int sys_sleep(time_t *secs, long *nanos) {
	syscall_clock_msleep(*secs * 1000 + *nanos / 1000000);
	return 0;
}

int sys_isatty(int fd) {
	// returns 0 if fd is a file, ENOTTY if it is not a file, but a tty
	return 0;
}

int sys_ttyname(int fd, char *buf, size_t size) {
	const char name[] = "MOS Stub TTY";
	if (size < sizeof(name))
		return 1;

	memcpy(buf, name, sizeof(name));
	buf[sizeof(name)] = 0;
	return 0;
}

uid_t sys_getuid() { return 0; }

uid_t sys_geteuid() { return 0; }

int sys_setuid(uid_t uid) {
	if (uid != 0)
		return 1;
	return 0;
}

gid_t sys_getgid() { return 0; }

gid_t sys_getegid() { return 0; }

int sys_gethostname(char *buffer, size_t bufsize) {
	memcpy(buffer, "mos", 3);
	return 0;
}

pid_t sys_getppid() { return syscall_get_parent_pid(); }

pid_t sys_getpgid(pid_t pid, pid_t *pgid) {
	*pgid = pid; // For now, we don't support process groups
	return 0;
}

int sys_setpgid(pid_t pid, pid_t pgid) { return 0; }

int sys_rmdir(const char *path) {
	long ret = syscall_vfs_rmdir(path);
	VERIFY_RET(ret);
	return 0;
}

int sys_unlinkat(int dirfd, const char *path, int flags) {
	MOS_UNUSED(flags);
	if (dirfd == AT_FDCWD)
		dirfd = AT_FDCWD;
	long ret = syscall_vfs_unlinkat(dirfd, path);
	VERIFY_RET(ret);
	return 0;
}

int sys_rename(const char *path, const char *new_path) {
	mlibc::infoLogger() << "stub sys_rename: " << path << " -> " << new_path << frg::endlog;
	return 0;
}

int sys_renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
	mlibc::infoLogger() << "stub sys_renameat: " << old_path << " -> " << new_path << frg::endlog;
	return 0;
}

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
	long ret = syscall_signal_mask_op(how, set, retrieve);
	VERIFY_RET(ret);
	return 0;
}

[[noreturn]] static __attribute__((naked)) void sigreturn_trampoline(void) {
	// move stack pointer to a0 and jump to syscall_signal_return
#if defined(__x86_64__)
	__asm__ volatile("movq %%rsp, %%rdi\ncall *%0\n" ::"a"(syscall_signal_return));
#elif defined(__riscv) && __riscv_xlen == 64
	__asm__ volatile("mv a0, sp\n"
	                 "mv a7, %0\n"
	                 "ecall\n" ::"r"(SYSCALL_signal_return));
#else
#error "Unsupported architecture"
#endif
}

int sys_sigaction(
    int sig, const struct sigaction *__restrict sigact, struct sigaction *__restrict sigact_old
) {
	if (sigact) {
		sigaction_t mos_sigact = {
		    .handler = sigact->sa_handler,
		    .sa_flags = sigact->sa_flags,
		    .sa_restorer = sigact->sa_restorer,
		};
		if (!(sigact->sa_flags & SA_RESTORER)) {
			mos_sigact.sa_restorer = sigreturn_trampoline;
			mos_sigact.sa_flags |= SA_RESTORER;
		}
		return !syscall_signal_register((signal_t)sig, &mos_sigact);
	} else {
		return !syscall_signal_register((signal_t)sig, nullptr);
	}
}

int sys_fork(pid_t *child) {
	long ret = syscall_fork();
	VERIFY_RET(ret);
	*child = ret;
	return 0;
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	long retpid = syscall_wait_for_process(pid, (u32 *)status, flags);
	VERIFY_RET(retpid);
	*ret_pid = retpid;
	return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
	long ret = syscall_execveat(AT_FDCWD, path, argv, envp, 0);
	VERIFY_RET(ret);
	return 0;
}

pid_t sys_getpid() { return syscall_get_pid(); }

int sys_kill(int pid, int sig) {
	long ret = syscall_signal_process(pid, sig);
	VERIFY_RET(ret);

	return 0;
}

int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	long ret = syscall_io_poll(fds, count, timeout);
	VERIFY_RET(ret);
	*num_events = ret;
	return 0;
}

int sys_pselect(
    int num_fds,
    fd_set *read_set,
    fd_set *write_set,
    fd_set *except_set,
    const struct timespec *timeout,
    const sigset_t *sigmask,
    int *num_events
) {
	int ret = syscall_io_pselect(num_fds, read_set, write_set, except_set, timeout, sigmask);
	if (ret) {
		*num_events = ret;
		return 0;
	}
	return 1;
}

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
	stat st;
	if (sys_stat(fsfd_target::path, dirfd, pathname, 0, &st))
		return 1;
	return 0;
}

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	mlibc::infoLogger() << "stub sys_ioctl: " << fd << ", " << request << ", " << arg
	                    << frg::endlog;
	return 0;
}

int sys_fcntl(int fd, int request, va_list args, int *result) {
	void *arg1 = va_arg(args, void *);
	long ret = syscall_fd_manipulate(fd, request, arg1);
	VERIFY_RET(ret);
	*result = ret;
	return 0;
}

int sys_tcgetattr(int fd, struct termios *attr) {
	mlibc::infoLogger() << "stub sys_tcgetattr: " << fd << ", " << attr << frg::endlog;
	return 0;
}

int sys_tcsetattr(int, int, const struct termios *attr) {
	mlibc::infoLogger() << "stub sys_tcsetattr: " << attr << frg::endlog;
	return 0;
}

int sys_dup(int fd, int flags, int *newfd) {
	MOS_UNUSED(flags);
	long ret = syscall_io_dup(fd);
	VERIFY_RET(ret);
	*newfd = ret;
	return 0;
}

int sys_dup2(int fd, int flags, int newfd) {
	MOS_UNUSED(flags);
	long ret = syscall_io_dup2(fd, newfd);
	VERIFY_RET(ret);
	return 0;
}

int sys_sysconf(int num, long *ret) {
	switch (num) {
		case _SC_ARG_MAX:
			return 2097152; // On linux, it is defined to 2097152 in most cases, so define it to be
			                // 2097152
		case _SC_PAGE_SIZE:
			return MOS_PAGE_SIZE;
		case _SC_OPEN_MAX:
			return 256;
		case _SC_PHYS_PAGES:
			return 1024;
		case _SC_NPROCESSORS_ONLN:
			return 1;
		case _SC_GETPW_R_SIZE_MAX:
			return NSS_BUFLEN_PASSWD;
		case _SC_GETGR_R_SIZE_MAX:
			return 1024;
		case _SC_CHILD_MAX:
			return 25;
		case _SC_JOB_CONTROL:
			return 1; // NO JOB CONTROL
		case _SC_NGROUPS_MAX:
			return 65536; // On linux, it is defined to 65536 in most cases, so define it to be
			              // 65536
		case _SC_LINE_MAX:
			return 2048; // Linux defines it as 2048.
		default:
			return -EINVAL;
	}
}

int sys_pipe(int *fds, int flags) {
	FDFlag mos_flags = {};
	if (flags & O_CLOEXEC)
		mos_flags |= FD_FLAGS_CLOEXEC;

	long ret = syscall_pipe(&fds[0], &fds[1], mos_flags);
	VERIFY_RET(ret);
	return 0;
}

int sys_fsync(int fd) {
	long ret = syscall_vfs_fsync(fd, false);
	VERIFY_RET(ret);
	return 0;
}

int sys_access(const char *path, int mode) {
	int retval = 0;
	stat st;
	if (sys_stat(fsfd_target::path, AT_FDCWD, path, 0, &st)) {
		retval = 1;
		goto done;
	}

	if (mode & R_OK) {
		if (!(st.st_mode & S_IRUSR || st.st_mode & S_IRGRP || st.st_mode & S_IROTH)) {
			retval = 1;
			goto done;
		}
	}
	if (mode & W_OK) {
		if (!(st.st_mode & S_IWUSR || st.st_mode & S_IWGRP || st.st_mode & S_IWOTH)) {
			retval = 1;
			goto done;
		}
	}
	if (mode & X_OK) {
		if (!(st.st_mode & S_IXUSR || st.st_mode & S_IXGRP || st.st_mode & S_IXOTH)) {
			retval = 1;
			goto done;
		}
	}

done:
	return retval;
}

int sys_getrlimit(int resource, struct rlimit *limit) {
	switch (resource) {
		case RLIMIT_NOFILE:
			limit->rlim_cur = 256;
			limit->rlim_max = 256;
			return 0;
		case RLIMIT_STACK:
			limit->rlim_cur = 8388608;
			limit->rlim_max = 8388608;
			return 0;
		case RLIMIT_AS:
			limit->rlim_cur = 4294967296;
			limit->rlim_max = 4294967296;
			return 0;
		case RLIMIT_CORE:
			limit->rlim_cur = 0;
			limit->rlim_max = 0;
			return 0;
		case RLIMIT_CPU:
			limit->rlim_cur = RLIM_INFINITY;
			limit->rlim_max = RLIM_INFINITY;
			return 0;
		case RLIMIT_DATA:
			limit->rlim_cur = RLIM_INFINITY;
			limit->rlim_max = RLIM_INFINITY;
			return 0;
		case RLIMIT_FSIZE:
			limit->rlim_cur = RLIM_INFINITY;
			limit->rlim_max = RLIM_INFINITY;
			return 0;
		case RLIMIT_LOCKS:
			limit->rlim_cur = 0;
			limit->rlim_max = 0;
			return 0;
		case RLIMIT_MEMLOCK:
			limit->rlim_cur = 65536;
			limit->rlim_max = 65536;
			return 0;
		case RLIMIT_MSGQUEUE:
			limit->rlim_cur = 819200;
			limit->rlim_max = 819200;
			return 0;
		case RLIMIT_NICE:
			limit->rlim_cur = 0;
			limit->rlim_max = 0;
			return 0;
		case RLIMIT_NPROC:
			limit->rlim_cur = 25;
			limit->rlim_max = 25;
			return 0;
		case RLIMIT_RSS:
			limit->rlim_cur = RLIM_INFINITY;
			limit->rlim_max = RLIM_INFINITY;
			return 0;
		case RLIMIT_RTPRIO:
			limit->rlim_cur = 0;
			limit->rlim_max = 0;
			return 0;
		case RLIMIT_SIGPENDING:
			limit->rlim_cur = 819200;
			limit->rlim_max = 819200;
			return 0;
		default:
			return EINVAL;
	}

	return 0;
}

int sys_fchmodat(int fd, const char *pathname, mode_t mode, int flags) {
	int mos_mode = 0;
	if (mode & S_IRUSR)
		mos_mode |= PERM_OWNER & PERM_READ;
	if (mode & S_IWUSR)
		mos_mode |= PERM_OWNER & PERM_WRITE;
	if (mode & S_IXUSR)
		mos_mode |= PERM_OWNER & PERM_EXEC;
	if (mode & S_IRGRP)
		mos_mode |= PERM_GROUP & PERM_READ;
	if (mode & S_IWGRP)
		mos_mode |= PERM_GROUP & PERM_WRITE;
	if (mode & S_IXGRP)
		mos_mode |= PERM_GROUP & PERM_EXEC;
	if (mode & S_IROTH)
		mos_mode |= PERM_OTHER & PERM_READ;
	if (mode & S_IWOTH)
		mos_mode |= PERM_OTHER & PERM_WRITE;
	if (mode & S_IXOTH)
		mos_mode |= PERM_OTHER & PERM_EXEC;

	// SUID, SGID, and sticky bits are not supported

	long ret = syscall_vfs_fchmodat(fd, pathname, mos_mode, 0);
	VERIFY_RET(ret);

	return 0;
}

int sys_chmod(const char *pathname, mode_t mode) {
	return sys_fchmodat(AT_FDCWD, pathname, mode, 0);
}

int sys_umask(mode_t mode, mode_t *old) {
	mlibc::infoLogger() << "stub sys_umask: " << mode << frg::endlog;
	return 0;
}

int sys_symlink(const char *target_path, const char *link_path) {
	long ret = syscall_vfs_symlink(link_path, target_path);
	VERIFY_RET(ret);
	return 0;
}

int sys_readlink(const char *pathname, char *buffer, size_t size) {
	long ret = syscall_vfs_readlinkat(AT_FDCWD, pathname, buffer, size);
	VERIFY_RET(ret);
	return 0;
}

} // namespace mlibc
