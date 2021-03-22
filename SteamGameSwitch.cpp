#include <iostream>
#include <JustBanMe.h>
#include <JustBanMe.cpp>

#pragma warning(disable:4996)

const ADDRESS targetOffset = 0x2bf22c;
const DWORD targetSize = 0x5;

int main()
{
	HANDLE handle = 0;
	handle = GetProcessHandleByName("steam.exe");
	DWORD pid = GetProcessIDByName("steam.exe");
	if (handle != NULL && pid != NULL) {
		std::cout << "pid: " << pid << "\n" << "handle: " << handle << "\n";
	}
	else {
		std::cout << "Failed\n";
	}
	
	ADDRESS steamclient = GetModuleBaseAddress(pid, L"steamclient.dll");
	std::cout << std::hex << steamclient << "\n";

	ADDRESS targetLocation = steamclient + targetOffset;
	BYTE* originalBytes = new BYTE[targetSize];
	ReadProcessMemory(handle, (LPVOID)targetLocation, originalBytes, targetSize, NULL);
	std::cout << std::hex << originalBytes << "\0\n";

	// Insert string
	LPVOID pathLocation = VirtualAllocEx(handle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	pathLocation = LPVOID(ADDRESS(pathLocation) + 1);
	LPCSTR path = "E:\\SteamLibrary\\steamapps\\common\\tempp2";
	LPCSTR exe = "lol.exe";
	LPVOID exeLocation = (LPVOID)((ADDRESS)pathLocation + strlen(path) + 1 + 1);
	DWORD oldProtect;
	VirtualProtectEx(handle, (LPVOID)pathLocation, MAX_PATH, PAGE_READWRITE, &oldProtect);
	WriteProcessMemory(handle, pathLocation, path, strlen(path), NULL);
	WriteProcessMemory(handle, exeLocation, exe, strlen(exe), NULL);

	// NOP it out
	BYTE* nopBytes = new BYTE[targetSize];
	// fill with NOPs
	for (int i = 0; i < targetSize; i++) {
		nopBytes[i] = 0x90;
	}

	// Flatten with NOPs, then write jmp
	VirtualProtectEx(handle, (LPVOID)targetLocation, targetSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(handle, (LPVOID)targetLocation, nopBytes, targetSize, NULL);

	size_t trampolineSize = 50;
	LPVOID trampoline = VirtualAllocEx(handle, NULL, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	UCHAR patch_stack[] = {
		0xc7,
		0x45,
		0xf8,

		// C7 45 F8 *addr*
		// mov [ebp-8], addr
	};
	size_t patch_stackSize = sizeof(patch_stack) / sizeof(patch_stack[0]);

	UCHAR patch_esi[] = {
		0xbe
		// BE *addr*
		// mov esi, *addr*
	};
	size_t patch_esiSize = sizeof(patch_esi) / sizeof(patch_esi[0]);

	UCHAR jmpPatch[] = {
		0xe9
	};
	WriteProcessMemory(handle, (LPVOID)targetLocation, &jmpPatch, 0x1, NULL); // write jmp instruction
	ADDRESS relativeDistance = (ADDRESS)trampoline - targetLocation - 0x5;
	WriteProcessMemory(handle, (LPVOID)(targetLocation+0x1), &relativeDistance, 0x4, NULL); // write jmp address

	ADDRESS lastLocation = (ADDRESS)trampoline;

	WriteProcessMemory(handle, (LPVOID)lastLocation, &patch_stack, patch_stackSize, NULL); // write patch_stack to trampoline
	WriteProcessMemory(handle, (LPVOID)(lastLocation+= patch_stackSize), &pathLocation, 0x4, NULL); // write path address

	WriteProcessMemory(handle, (LPVOID)(lastLocation+=0x4), &patch_esi, patch_esiSize, NULL); // write patch_esi to trampoline
	WriteProcessMemory(handle, (LPVOID)(lastLocation += patch_esiSize), &exeLocation, 0x4, NULL); // write exe address


	WriteProcessMemory(handle, (LPVOID)(lastLocation+=4), originalBytes, targetSize, NULL); // write stolen bytes

	// write return jmp
	WriteProcessMemory(handle, (LPVOID)(lastLocation += targetSize), &jmpPatch, 0x1, NULL);

	relativeDistance = (ADDRESS)targetLocation + targetSize - lastLocation - 5;
	WriteProcessMemory(handle, (LPVOID)(lastLocation + 1), &relativeDistance, 0x4, NULL);


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