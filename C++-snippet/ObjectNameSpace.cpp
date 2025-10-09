#include <Windows.h>
#include <iostream>



int main() {

	HANDLE handle = CreateEvent(nullptr, TRUE, FALSE, NULL);


	getchar();
	printf("Hello World");


	return 0;
}