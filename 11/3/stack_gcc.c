#include <stdio.h>

int MYFUNC(int times, char * string){
	int local;
	for (local = 0; local <= times; local++){
		printf("%d: %s\n", local, string);
	}
	return 99;
}
int main(){
	MYFUNC(10, "printme");
	return 0;
}
