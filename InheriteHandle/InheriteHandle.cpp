#include <Windows.h>
#include <iostream>
#include <string>

int main()
{
	HANDLE hEVENT = CreateEvent(NULL, TRUE, FALSE, L"SHAREITHPROCESS");
	SetHandleInformation(hEVENT, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	wchar_t name[] = L"Notepad";
	std::wstring param = name + std::to_wstring((ULONG_PTR)hEVENT);

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	CreateProcessW(nullptr, param.data(), nullptr, nullptr, TRUE, HIGH_PRIORITY_CLASS, nullptr, nullptr, &si, &pi);

}