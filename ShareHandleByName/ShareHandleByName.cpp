#include <Windows.h>
#include <iostream>


int main()
{
	HANDLE hEVENT = CreateEvent(NULL, TRUE, FALSE, L"ShutdownEVENT");
	if (!hEVENT)
	{
		printf("ERROR: %u\n", GetLastError());
		return 1;
	}

	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		std::cout << "Worker Process ... Wait for shutdown notification";
		WaitForSingleObject(hEVENT, INFINITE);
		std::cout << "Shutdown ......";
	}
	else
	{
		std::cout << "Controller Process, Press any key to shutdown workers" << std::endl;
		getchar();
		SetEvent(hEVENT);
	}

	CloseHandle(hEVENT);




}