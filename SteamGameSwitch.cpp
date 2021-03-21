#include <iostream>
#include <JustBanMe.h>
#include <JustBanMe.cpp>

#pragma warning(disable:4996)

const ADDRESS targetOffset = 0x2bf252;
const DWORD targetSize = 0x5;

int main()
{
	HANDLE handle = GetProcessHandleByName("steam.exe");
	DWORD pid = GetProcessIDByName("steam.exe");
	std::cout << "pid: " << pid << "\n" << "handle: " << handle << "\n";
	
	ADDRESS steamclient = GetModuleBaseAddress(pid, L"steamclient.dll");
	std::cout << std::hex << steamclient << "\n";

	ADDRESS targetLocation = steamclient + targetOffset;
	BYTE* originalBytes = new BYTE[targetSize];
	ReadProcessMemory(handle, (LPVOID)targetLocation, originalBytes, targetSize, NULL);
	std::cout << std::hex << originalBytes << "\0\n";

	// Insert string
	LPVOID stringLocation = VirtualAllocEx(handle, NULL, 255, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LPCSTR path = "E:\\SteamLibrary\\steamapps\\common\\tempp2\\lol.exe";
	WriteProcessMemory(handle, stringLocation, path, strlen(path), NULL);

	// NOP it out
	BYTE* nopBytes = new BYTE[targetSize];
	// fill with NOPs
	for (int i = 0; i < targetSize; i++) {
		nopBytes[i] = 0x90;
	}

	// Flatten with NOPs, then write jmp
	DWORD oldProtect;
	VirtualProtectEx(handle, (LPVOID)targetLocation, targetSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(handle, (LPVOID)targetLocation, nopBytes, targetSize, NULL);
	size_t trampolineSize = 256;
	LPVOID trampoline = VirtualAllocEx(handle, NULL, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	UCHAR bytecode[] = {
		0xb8, // mov
	};
	UCHAR jmpPatch[] = {
		0xe9
	};
	WriteProcessMemory(handle, (LPVOID)targetLocation, &jmpPatch, 0x1, NULL); // write jmp instruction
	ADDRESS relativeDistance = (ADDRESS)trampoline - targetLocation - 0x5;
	WriteProcessMemory(handle, (LPVOID)(targetLocation+0x1), &relativeDistance, 0x4, NULL); // write jmp address

	WriteProcessMemory(handle, (LPVOID)trampoline, &bytecode, 0x1, NULL); // write first byte to trampoline
	WriteProcessMemory(handle, (LPVOID)((ADDRESS)trampoline+0x1), &stringLocation, 0x4, NULL); // write string address

	WriteProcessMemory(handle, (LPVOID)((ADDRESS)trampoline + 0x5), originalBytes+0x3, 0x5, NULL); // write stolen bytes
	UCHAR pushEAX[] = {
		0x50
	};
	WriteProcessMemory(handle, (LPVOID)((ADDRESS)trampoline + 0x10), &pushEAX, 0x1, NULL); // write stolen bytes


	VirtualProtectEx(handle, (LPVOID)targetLocation, targetSize, oldProtect, &oldProtect);
	getchar();
}

/*
* step 1: get module address
* step 2: apply offset or signature scan
* 
* step 4: write string to codecave
* step 3: save original bytes
* step 5: patch instruction to "mov eax, *string location*"
*/