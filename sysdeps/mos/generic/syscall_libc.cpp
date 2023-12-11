// SPDX-License-Identifier: GPL-3.0-or-later

#include "abi-bits/utsname.h"
#include "abi-bits/vm-flags.h"
#include "bits/ensure.h"
#include "mlibc/ansi-sysdeps.hpp"
#include "mlibc/internal-sysdeps.hpp"
#include "mlibc/posix-sysdeps.hpp"
#include "mlibc/tcb.hpp"
#include "mos/filesystem/fs_types.h"

#include <dirent.h>
#include <errno.h>
#include <mos/mos_global.h>
#include <mos/syscall/usermode.h>
#include <string.h>
#include <sys/mman.h>

extern "C" void __mlibc_start_thread(void *);

extern "C" void __mlibc_enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	// Wait until our parent sets up the TID:
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED))
		mlibc::sys_futex_wait(&tcb->tid, 0, nullptr);

	if (mlibc::sys_tcb_set(tcb))
		__ensure(!"sys_tcb_set() failed");

	tcb->invokeThreadFunc(entry, user_arg);

	auto self = reinterpret_cast<Tcb *>(tcb);

	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
	mlibc::sys_futex_wake(&self->didExit);

	mlibc::sys_thread_exit();
}

namespace mlibc {
int sys_prepare_stack(
    void **stack,
    void *entry,
    void *user_arg,
    void *tcb,
    size_t *stack_size,
    size_t *guard_size,
    void **stack_base
) {
	static constexpr auto default_stacksize = MOS_STACK_PAGES_USER;
	if (!*stack_size)
		*stack_size = default_stacksize;
	*guard_size = 0;

	if (*stack)
		*stack_base = *stack;
	else {
		*stack_base =
		    mmap(nullptr, *stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (*stack_base == MAP_FAILED)
			return errno;
	}

	uintptr_t *sp =
	    reinterpret_cast<uintptr_t *>(reinterpret_cast<uintptr_t>(*stack_base) + *stack_size);

	*--sp = reinterpret_cast<uintptr_t>(tcb);
	*--sp = reinterpret_cast<uintptr_t>(user_arg);
	*--sp = reinterpret_cast<uintptr_t>(entry);
	*stack = reinterpret_cast<void *>(sp);
	return 0;
}

int sys_clone(void *tcb, pid_t *pid_out, void *stack) {
	MOS_UNUSED(tcb);
	pid_t pid = syscall_create_thread("thread", __mlibc_start_thread, NULL, 0, stack);
	if (pid < 0) {
		return errno;
	}

	*pid_out = pid;
	return 0;
}

int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
	MOS_UNUSED(max_size);
	*bytes_read = syscall_io_read(handle, buffer, max_size);
	if (IS_ERR_VALUE(*bytes_read))
		return -static_cast<int>(*bytes_read);

	// iterate over the buffer and set the d_reclen
	for (size_t i = 0; i < *bytes_read;) {
		auto ent = reinterpret_cast<struct dirent *>(reinterpret_cast<uintptr_t>(buffer) + i);
		switch ((file_type_t)ent->d_type) {
			case FILE_TYPE_REGULAR:
				ent->d_type = DT_REG;
				break;
			case FILE_TYPE_DIRECTORY:
				ent->d_type = DT_DIR;
				break;
			case FILE_TYPE_SYMLINK:
				ent->d_type = DT_LNK;
				break;
			case FILE_TYPE_CHAR_DEVICE:
				ent->d_type = DT_CHR;
				break;
			case FILE_TYPE_BLOCK_DEVICE:
				ent->d_type = DT_BLK;
				break;
			case FILE_TYPE_NAMED_PIPE:
				ent->d_type = DT_FIFO;
				break;
			case FILE_TYPE_SOCKET:
				ent->d_type = DT_SOCK;
				break;
			case FILE_TYPE_UNKNOWN:
				ent->d_type = DT_UNKNOWN;
				break;
		}
		i += ent->d_reclen;
	}

	return 0;
}

int sys_uname(struct utsname *buf) {
	strcpy(buf->sysname, "MOS");
	strcpy(buf->nodename, "MOS");
	strcpy(buf->release, "0.0.1");
	strcpy(buf->version, "0.0.1");
	strcpy(buf->machine, "x86_64");
	strcpy(buf->domainname, "");
	return 0;
}

int sys_thread_setname(void *tcb, const char *name) {
	Tcb *t = reinterpret_cast<Tcb *>(tcb);
	long result = syscall_thread_setname(t->tid, name);
	if (IS_ERR_VALUE(result))
		return -result;
	return 0;
}

int sys_thread_getname(void *tcb, char *name, size_t size) {
	Tcb *t = reinterpret_cast<Tcb *>(tcb);
	long result = syscall_thread_getname(t->tid, name, size);
	if (IS_ERR_VALUE(result))
		return -result;
	return 0;
}

int sys_gettid() { return syscall_get_tid(); }

int sys_memfd_create(const char *name, int flags, int *fd) {
	long result = syscall_memfd_create(name, flags);
	if (IS_ERR_VALUE(result))
		return -result;
	*fd = result;
	return 0;
}

void sys_yield() { syscall_yield_cpu(); }

} // namespace mlibc
