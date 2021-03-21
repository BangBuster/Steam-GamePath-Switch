#pragma once
#ifndef justBanme
#define justBanme
#include "includes.h"

extern bool pressed;

extern bool hasEnding(std::string const &fullString, std::string const &ending);

extern HMODULE PrintModules(DWORD processID);
extern DWORD GetModuleBaseAddress(DWORD processID, LPCSTR moduleName);
extern DWORD GetProcessID(LPCSTR processName);
extern HANDLE GetHandle_READ(DWORD processID);
extern HANDLE GetHandle_ALL(DWORD processID);
extern VOID ReadMemory(HANDLE handle, const LPCVOID &address, LPCVOID value);
extern float calculateDistance(float point1x, float point1y, float point2x, float point2y);


#endif