#include <windows.h>
#include <iostream>

int main()
{
	const char* dllpath = "C:\\users\public\\test.dll";
	long pid = 0;

	HANDLE pr = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (pr)
	{
		void* loc = VirtualAllocEx(pr, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(pr, loc, dllpath, strlen(dllpath), 0);

		HANDLE Hthread = CreateRemoteThread(pr, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
		CloseHandle(pr);
	}
}