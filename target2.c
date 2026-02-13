#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[64];
    gets(buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable();
    }
    return 0;
}
