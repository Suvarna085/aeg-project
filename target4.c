#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[32];
    char dummy[16];
    gets(buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && argv[1][0] == 'B') {
        vulnerable();
    }
    return 0;
}
