#include <unistd.h>
#include <string.h>
int main(void) {
    const char *m = "hello from kemu aarch64 guest\n";
    write(1, m, strlen(m));
    return 0;
}
