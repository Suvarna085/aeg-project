#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[64];
    gets(buffer);
    puts(buffer);   // info leak primitive — prints input back
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);  // disable buffering so leak arrives immediately
    vulnerable();
    return 0;
}
