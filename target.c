#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[64];
    gets(buffer);
}

int main() {
    vulnerable();
    return 0;
}
