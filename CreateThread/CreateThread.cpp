#include <Windows.h>
#include <iostream>

DWORD DoWork(PVOID param) {
	std::cout << "Thread is Running...!" << std::endl;

	for (size_t i = 0; i < 10; i++)
	{
		std::cout << i << std::endl;
		Sleep(1000);
	}

	return 5;
}


int main()
{
	DWORD ExitCode;
	HANDLE Hthread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DoWork, nullptr, 0, nullptr);
	WaitForSingleObject(Hthread, 10);
	GetExitCodeThread(Hthread, &ExitCode);
	std::cout << ExitCode << std::endl;

	CloseHandle(Hthread);
}