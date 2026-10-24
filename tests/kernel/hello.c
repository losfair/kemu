#include <stdio.h>
#include <sys/utsname.h>
int main(int argc, char **argv)
{
	struct utsname u;
	uname(&u);
	printf("hello from %s (%s), argc=%d argv[0]=%s\n", u.machine, u.sysname, argc, argv[0]);
	return 42;
}
