#include "stdio.h"
#include "Windows.h"

int main() {
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	WCHAR name[] = L"notepad.exe";
	BOOL Created = CreateProcessW(NULL, name, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	printf("PID: %s", pi.dwProcessId);
}