#include <bits/ensure.h>
#include <mlibc/elf/startup.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/auxv.h>

// defined by the POSIX library
void __mlibc_initLocale();

extern "C" uintptr_t *__dlapi_entrystack();
extern "C" void __dlapi_enter(uintptr_t *entry_stack);

extern char **environ;
static mlibc::exec_stack_data __mlibc_stack_data;

typedef int (*main_fn_type)(int argc, char *argv[], char *env[]);

extern "C" void __mlibc_entry(uintptr_t *entry_stack, main_fn_type main_fn) {
	__dlapi_enter(entry_stack);
	auto result = main_fn(__mlibc_stack_data.argc, __mlibc_stack_data.argv, environ);
	exit(result);
}
