#include <Windows.h>
#include <iostream>

FARPROC messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
BYTE OldCode[12] = { 0x00 };
BYTE HookCode[12] = { 0x48,0xB8,0x90,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0xFF,0xE0 };

int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	std::cout << lpText << std::endl;

	//Unhook Func
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, OldCode, sizeof(OldCode), &bytesWritten);


	return MessageBoxA(NULL, lpText, lpCaption, uType);
}

int main()
{
	MessageBoxA(NULL, "hi", "hi", MB_OK);

	HINSTANCE library = LoadLibraryA("user32.dll");
	SIZE_T bytesRead = 0;

	messageBoxAddress = GetProcAddress(library, "MessageBoxA");

	ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, OldCode, 12, &bytesRead);

	void* hookedMessageBoxAddress = &HookedMessageBox;

	*(PINT64)(HookCode + 2) = (UINT64)HookedMessageBox;

	WriteProcessMemory(GetCurrentProcess(), messageBoxAddress, HookCode, sizeof(HookCode), &bytesWritten);

	MessageBoxA(NULL, "hi", "hi", MB_OK);

	return 0;

}