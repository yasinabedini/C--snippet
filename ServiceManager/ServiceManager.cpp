#include <iostream>
#include <Windows.h>


//Global 
SERVICE_STATUS_HANDLE g_hService;
SERVICE_STATUS g_status;
HANDLE G_hStopEvent;

//Special PortoType
void WINAPI EventServiceMain(DWORD Argcount, LPSTR* Args) {

}


int main()
{
	WCHAR name[] = L"EventService";
	const SERVICE_TABLE_ENTRY table[] = {
		{name, (LPSERVICE_MAIN_FUNCTIONW)EventServiceMain},
		{nullptr,nullptr}
	};

	StartServiceCtrlDispatcher(table);
}