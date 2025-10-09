#include <iostream>
#include <Windows.h>

extern "C" int iProcessInJob2(HANDLE);

int main()
{
	DWORD processId = 1222;
	HANDLE OP = OpenProcess(PROCESS_ALL_ACCESS, false, processId);


	NTSTATUS result = iProcessInJob2(OP);

	int m = 2;
}