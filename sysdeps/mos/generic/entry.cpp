#include <bits/ensure.h>
#include <mlibc/elf/startup.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/auxv.h>

extern "C" void __dlapi_enter(uintptr_t *entry_stack);

extern char **environ;

typedef int (*main_fn_type)(int argc, char *argv[], char *env[]);

extern "C" void __mlibc_entry(uintptr_t *entry_stack, main_fn_type main_fn) {
	__dlapi_enter(entry_stack);
	auto result = main_fn(mlibc::entry_stack.argc, mlibc::entry_stack.argv, environ);
	exit(result);
}
