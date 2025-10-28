#include <Windows.h>
#include <iostream>

int main()
{
	HANDLE PR = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 5656);
	HANDLE DuplicatedHandle;
	DuplicateHandle(PR, (HANDLE)0xE0, GetCurrentProcess(), &DuplicatedHandle, DUPLICATE_SAME_ACCESS, FALSE, 0);
}