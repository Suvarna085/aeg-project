#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[64];
    gets(buffer);
}

int main() {
    int i;
    int sum = 0;
    for (i = 0; i < 10; i++) {
        sum += i;
    }
    if (sum == 45) {
        vulnerable();
    }
    return 0;
}
