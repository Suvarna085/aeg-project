#include<stdio.h>
#include<string.h>

void safe_function(){
	char buffer[256];
	gets(buffer);
	printf("You entered: %s\n", buffer);
}

int main(){
	safe_function();
	return 0;
}
