#include <stdio.h>
#include <elf.h>
extern char **environ;
int main(int argc, char **argv) {
	char **e = environ; while (*e) e++;
	Elf64_auxv_t *a = (Elf64_auxv_t *)(e + 1);
	for (; a->a_type; a++) printf("AT %2lu = %#lx\n", a->a_type, a->a_un.a_val);
	printf("sp-align argv=%p\n", (void *)argv);
	return 0;
}
