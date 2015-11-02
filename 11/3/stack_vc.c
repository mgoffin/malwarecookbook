// stack.cpp : Function used to show the use of the stack pane

#include "stdafx.h"
#include "stdio.h"

int MYFUNC(int times, char * string){
	int local;
	for (local = 0; local <= times; local++){
		printf("%d: %s\n", local, string);
	}
	return 99;
}

int _tmain(int argc, _TCHAR* argv[])
{
	MYFUNC(10, "printme");
	return 0;
}

