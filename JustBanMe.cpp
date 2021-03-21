#include "JustBanMe.h"
//bool pressed = false;
DWORD GetModuleBaseAddress(DWORD processID, LPCSTR moduleName)
{
	HANDLE snapshot;
	MODULEENTRY32 pe32;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	pe32.dwSize = sizeof(MODULEENTRY32);
	
	if (Module32First(snapshot, &pe32)) {
		if (!strcmp(moduleName, pe32.szModule)) {
			CloseHandle(snapshot);
			return (DWORD)pe32.modBaseAddr;
		}
	}
	else {
		return false;
	}

	while (Module32Next(snapshot, &pe32)) {
		//std::cout << pe32.szModule << "\n";
		if (!strcmp(moduleName, pe32.szModule)) {
			CloseHandle(snapshot);
			return (DWORD)pe32.modBaseAddr;
		}
	}
	DWORD WINAPI GetLastError(void);
	std::cout << GetLastError();
	CloseHandle(snapshot);
	return false;
}


HANDLE GetHandle_READ(DWORD processID) {
	if (processID == 0) {
		return (HANDLE)false;
	}
	HANDLE handle = OpenProcess(PROCESS_VM_READ, false, processID);
	if (!OpenProcess) {
		return (HANDLE)false;
	}
	else {
		return handle;
	}
}
HANDLE GetHandle_ALL(DWORD processID) {
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
	if (!OpenProcess) {
		return (HANDLE)false;
	}
	else {
		return handle;
	}
}
bool hasEnding(std::string const &fullString, std::string const &ending) {
	if (fullString.length() >= ending.length()) {
		return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
	}
	else {
		return false;
	}
}
DWORD GetProcessID(LPCSTR processName) {
	HWND hwnd = FindWindowA(NULL, processName);
	if (!hwnd) {
		return false;
	}
	DWORD procID;
	if (!GetWindowThreadProcessId(hwnd, &procID)) {
		return false;
	}
	else {
		return procID;
	}
}
VOID ReadMemory(HANDLE handle, const LPCVOID &address, LPCVOID value) {
	ReadProcessMemory(handle, (LPCVOID)(address), &value, sizeof(value), NULL);
}
float calculateDistance(float point1x, float point1y, float point2x, float point2y) {
	float d = sqrt((float)pow((point2x - point1x), 2) + (float)pow((point2y - point1y), 2));
	return d;
}