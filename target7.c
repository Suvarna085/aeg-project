#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[64];
    gets(buffer);
}

int main() {
    printf("Enter input: ");
    vulnerable();
    return 0;
}
