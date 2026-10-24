#include <stdio.h>
int main(int c, char **v) { for (int i = 1; i < c; i++) { FILE *f = fopen(v[i], "r"); int ch; if (!f) { perror(v[i]); continue; } while ((ch = fgetc(f)) != EOF) putchar(ch); fclose(f);} return 0; }
