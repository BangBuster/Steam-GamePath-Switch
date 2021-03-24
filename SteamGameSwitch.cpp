#include <iostream>
#include <JustBanMe.h>
#include <JustBanMe.cpp>
#include <vector>
#include <commdlg.h>

#pragma warning(disable:4996)

int main(int argc, char* argv[])
{
	// Get path of exe from user
	// commandline or explorer prompt
	std::string input(MAX_PATH, '\0');
	if (argc > 1) {
		input = argv[1];
	}
	else {
		OPENFILENAMEA ofn = { };
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = NULL;
		ofn.lpstrFilter = "Executables only\0*.exe;*.com\0\0";
		ofn.lpstrFile = &input[0];
		ofn.nMaxFile = MAX_PATH;
		ofn.lpstrTitle = "Select Your Executable";
		ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;

		GetOpenFileNameA(&ofn);
	}
	auto pos = input.find_last_of('\\');
	std::string exe = input.substr(pos + 1);
	std::string path = input.substr(0, pos);

	const DWORD targetSize = 0x5;

	HANDLE handle = GetProcessHandleByName("steam.exe");
	DWORD pid = GetProcessIDByName("steam.exe");
	if (handle == NULL || pid == NULL) {
		std::cout << "Failed\n";
		return 1;
	}
	
	module steamclient = GetModule(pid, L"steamclient.dll");
	
	// signature is 5 bytes away the real target to allow unhooking
	BYTE signature[] = {
		0x56, 0x0F, 0x45, 0xC8, 0x8D, 0x45, 0xFC, 0x51, 0x68, '?', '?', '?', '?', 0x50
	};
	ADDRESS toHook = (ADDRESS)signatureScan(handle, steamclient, signature, sizeof(signature)).at(0)-5;

	
	// Insert string
	ADDRESS pathLocation = (ADDRESS)VirtualAllocEx(handle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	pathLocation++; // otherwise steam crashes

	ADDRESS exeLocation = (ADDRESS)pathLocation + path.length() + 1;
	WriteProcessMemory(handle, (LPVOID)pathLocation, path.c_str(), path.length(), NULL);
	WriteProcessMemory(handle, (LPVOID)exeLocation, exe.c_str(), path.length(), NULL);

	DWORD oldProtect;
	VirtualProtectEx(handle, (LPVOID)toHook, targetSize, PAGE_EXECUTE_READWRITE, &oldProtect);

	BYTE* originalBytes = new BYTE[targetSize];
	ReadProcessMemory(handle, (LPVOID)toHook, originalBytes, targetSize, NULL);

	size_t caveSize = 50;
	LPVOID cave = VirtualAllocEx(handle, NULL, caveSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	// Create hook
	ADDRESS hookJmpOffset = (ADDRESS)cave - toHook - 0x5;
	std::vector<BYTE> hookcode = {
		0xe9,
		(BYTE)((hookJmpOffset >> (4 * 8)) & 0xFF),
		(BYTE)((hookJmpOffset >> (1 * 8)) & 0xFF),
		(BYTE)((hookJmpOffset >> (2 * 8)) & 0xFF),
		(BYTE)((hookJmpOffset >> (3 * 8)) & 0xFF),
	};

	// Create shellcode
	std::vector<BYTE> shellcode = {
		0xc7,
		0x45,
		0xf8,
		(BYTE)((pathLocation >> (4 * 8)) & 0xFF),
		(BYTE)((pathLocation >> (1 * 8)) & 0xFF),
		(BYTE)((pathLocation >> (2 * 8)) & 0xFF),
		(BYTE)((pathLocation >> (3 * 8)) & 0xFF),
		// 0xC7 0x45 0xF8 *addr*
		// mov [ebp-8], addr

		0xbe,
		(BYTE)((exeLocation >> (4 * 8)) & 0xFF),
		(BYTE)((exeLocation >> (1 * 8)) & 0xFF),
		(BYTE)((exeLocation >> (2 * 8)) & 0xFF),
		(BYTE)((exeLocation >> (3 * 8)) & 0xFF),
		// 0xBE *addr*
		// mov esi, *addr*
	};
	// Create the stolen bytes
	for (int i = 0; i < targetSize; i++) {
		shellcode.push_back((BYTE)originalBytes[i]);
	}
	// Create return
	ADDRESS returnJmpOffset = (toHook + targetSize) - ((ADDRESS)cave + shellcode.size()) - 5;
	shellcode.push_back(0xe9); 
	shellcode.push_back((BYTE)((returnJmpOffset >> (4 * 8)) & 0xFF));
	shellcode.push_back((BYTE)((returnJmpOffset >> (1 * 8)) & 0xFF));
	shellcode.push_back((BYTE)((returnJmpOffset >> (2 * 8)) & 0xFF));
	shellcode.push_back((BYTE)((returnJmpOffset >> (3 * 8)) & 0xFF));

	// apply hook here
	WriteProcessMemory(handle, (LPVOID)toHook, &hookcode[0], hookcode.size(), NULL); // apply hook
	WriteProcessMemory(handle, (LPVOID)cave, &shellcode[0], shellcode.size(), NULL);  // write shellcode


	VirtualProtectEx(handle, (LPVOID)toHook, targetSize, oldProtect, &oldProtect);
}