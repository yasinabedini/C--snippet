#include <iostream>
#include <Windows.h>

FARPROC MessageboxAddr = NULL;
char MsgOriginal[6] = {};



int
WINAPI
HookedMessageBoxA(_In_opt_ HWND hWnd,_In_opt_ LPCSTR lpText,_In_opt_ LPCSTR lpCaption,_In_ UINT uType)
{
	std::cout << lpText << std::endl;

	//Unhook Func
	WriteProcessMemory(GetCurrentProcess(), MessageboxAddr, MsgOriginal, 6, NULL);


	return MessageBoxA(hWnd,lpText,lpCaption,uType);
}

//BYTE jmp[6] = { 0xE9,0X00,0X00,0X00,0X00,0xc3 };  //Senario2

int main()
{
	MessageBoxA(NULL, "Hello", "Windows Internals Class", 0);

	HINSTANCE library = LoadLibraryA("User32.dll");

	MessageboxAddr = GetProcAddress(library, "MessageBoxA");

	ReadProcessMemory(GetCurrentProcess(), MessageboxAddr, MsgOriginal, 6, NULL);

	void* hookedmsgbox = &HookedMessageBoxA;

	//DWORD offset = ((DWORD)HookedMessageBoxA - (DWORD)MessageboxAddr - 5); //Senario2

	char hookstruct[6] = { 0 };

	memcpy_s(hookstruct, 1, "\x68", 1);
	memcpy_s(hookstruct + 1, 4, &hookedmsgbox, 4);
	memcpy_s(hookstruct + 5, 1, "\xc3", 1);

	//memcpy(jmp + 1, &offset, 4); //Senario2
	//memcpy(hookstruct, jmp, 6);  //Senario2


	WriteProcessMemory(GetCurrentProcess(), (LPVOID)MessageboxAddr, hookstruct, sizeof(hookstruct), NULL);

	MessageBoxA(NULL, "Hello", "Windows Internals Class", 0);


	std::cout << "End of code" << std::endl;
}