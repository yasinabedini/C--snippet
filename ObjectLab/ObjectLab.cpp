#include <windows.h>
#include <iostream>



int main() {

	HANDLE handle = CreateEvent(nullptr, TRUE, FALSE, L"Global\\WindowsInternalTestEvent");


	getchar();
	printf("Hello World!");


	return 0;
}