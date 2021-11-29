#include <iostream>
#include <JustBanMe.h>
#include <JustBanMe.cpp>
#include <vector>
#include <commdlg.h>

#pragma warning(disable:4996)

// Used for unhooking
const BYTE unhook_bytes[] = { 0x8b, 0xff, 0x55, 0x8b, 0xec }; // ITS HARDCODED :( TRY TO FIX IT
int logAndExit(std::string logMessage);

BOOL unhook(HANDLE handle, LPVOID toHook);

int main(int argc, char* argv[])
{
	const DWORD targetSize = 0x5;

	HANDLE handle = GetProcessHandleByName("steam.exe");
	DWORD pid = GetProcessIDByName("steam.exe");
	if (handle == NULL || pid == NULL) {
		MessageBox(NULL, "Failed to find steam!", "", MB_ICONWARNING | MB_OK);
		return 1;
	}

	module kerneldll = GetModule(pid, L"KERNEL32.DLL");

	if (kerneldll.dwSize == 0) {
		return logAndExit("couldn't find kernel32.dll");
	}

	// Get path of exe from user
	// commandline or explorer prompt
	std::wstring input(MAX_PATH, '\0');
	if (argc > 1) {
		//input = argv[1]; TODO: convert
	}
	else {
		OPENFILENAMEW ofn = { };
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = NULL;
		ofn.lpstrFilter = L"Executables only\0*.exe;*.com\0\0";
		ofn.lpstrFile = &input[0];
		ofn.nMaxFile = MAX_PATH;
		ofn.lpstrTitle = L"Select Your Executable";
		ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;

		GetOpenFileNameW(&ofn);
	}

	std::wstring exe, path;
	auto pos = input.find_last_of('\\');
	exe = input.substr(pos + 1);
	path = input.substr(0, pos);

	// search for CreateProcessW address in own kernel32.dll
	const auto kernel32handle = GetModuleHandle("kernel32.dll");
	if (!kernel32handle) {
		return logAndExit("Couldn't get a handle to kernel32");
	}

	const ADDRESS createProcessAddress = (ADDRESS)GetProcAddress(kernel32handle, "CreateProcessW");
	if (!createProcessAddress) {
		DWORD latestError = GetLastError();
		// couldnt get address to CreateProcessW
		return logAndExit("Couldn't get address to target function");
	}

	const auto CREATE_PROCESS_W_LENGTH = 10;

	BYTE* originalCreateProcess = new BYTE[CREATE_PROCESS_W_LENGTH];
	memcpy(originalCreateProcess, (LPVOID)createProcessAddress, CREATE_PROCESS_W_LENGTH);

	// read the bytes on target process using the local address found above

	DWORD old_CPW_Protect;
	const auto vpres =
		VirtualProtectEx(handle, (LPVOID)createProcessAddress, targetSize, PAGE_EXECUTE_READWRITE, &old_CPW_Protect);
	if (!vpres) {
		return logAndExit("Couldn't get permissions to CreateProcessW on target process");
	}
	re_read_bytes:
	BYTE* createProcessBytes = new BYTE[CREATE_PROCESS_W_LENGTH];
	ZeroMemory(createProcessBytes, CREATE_PROCESS_W_LENGTH);
	const auto cpResult = ReadProcessMemory(handle, (LPVOID)createProcessAddress, createProcessBytes, CREATE_PROCESS_W_LENGTH, NULL);
	if (!cpResult) {
		return logAndExit("Couldn't read from target process");
	}

	// unhook and return original bytes if exe wasnt chosen
	if (input.at(0) == NULL) {
		return unhook(handle, (LPVOID)createProcessAddress);
	}

	const auto firstByte = createProcessBytes[0];
	if (firstByte == 0xe9) {
		// unhook
		const auto unhookRet = unhook(handle, (LPVOID)createProcessAddress);
		if (!unhookRet) {
			return logAndExit("Failed to unhook existing hook");
		}
		goto re_read_bytes;
	}

	// inject path string
	std::wstring fullPath = path + L"\\" + exe;

	ADDRESS fullPathLocation = (ADDRESS)VirtualAllocEx(handle, NULL, fullPath.length(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	fullPathLocation++; // otherwise steam crashes

	ADDRESS onlyPathLocation = (ADDRESS)VirtualAllocEx(handle, NULL, path.length(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	onlyPathLocation++;

	const auto exeRet = WriteProcessMemory(handle, (LPVOID)fullPathLocation, fullPath.c_str(), fullPath.length(), NULL);
	if (exeRet == 0) {
		std::cout << "Something went wrong while writing path to steam process!\n";
		return 1;
	}

	const auto pathRet = WriteProcessMemory(handle, (LPVOID)onlyPathLocation, path.c_str(), path.length(), NULL);
	if (pathRet == 0) {
		std::cout << "Something went wrong while writing path to steam process!\n";
		return 1;
	}

	// perform the hook procedure

	// first, create our function (modFunction = function that replaces the previous path string with our string)
	ADDRESS modFunction = (ADDRESS)VirtualAllocEx(handle, NULL, 0x256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	std::vector<BYTE> modShellcode = {
		0x83,
		0xfe,
		0x00, // cmp esi, 0 
		
		0x74, // je
		0x10,

		0xc7, // 
		0x44, // 
		0x24, // mov DWORD PTR [esp+0x4],0x5
		0x08, // 
		(BYTE)((fullPathLocation >> (4 * 8)) & 0xFF),
		(BYTE)((fullPathLocation >> (1 * 8)) & 0xFF),
		(BYTE)((fullPathLocation >> (2 * 8)) & 0xFF),
		(BYTE)((fullPathLocation >> (3 * 8)) & 0xFF),

		0xc7, // 
		0x44, // 
		0x24, // mov DWORD PTR [esp+0x8],0x5
		0x0C, // 
		(BYTE)((fullPathLocation >> (4 * 8)) & 0xFF),
		(BYTE)((fullPathLocation >> (1 * 8)) & 0xFF),
		(BYTE)((fullPathLocation >> (2 * 8)) & 0xFF),
		(BYTE)((fullPathLocation >> (3 * 8)) & 0xFF),
	};

	const auto relativeReturnJmp = (createProcessAddress) - (modFunction + modShellcode.size()) - 5;

	std::vector<BYTE> returnJmpShellcode = {
		0xe9,
		(BYTE)((relativeReturnJmp >> (4 * 8)) & 0xFF),
		(BYTE)((relativeReturnJmp >> (1 * 8)) & 0xFF),
		(BYTE)((relativeReturnJmp >> (2 * 8)) & 0xFF),
		(BYTE)((relativeReturnJmp >> (3 * 8)) & 0xFF),
	};

	// write stolen bytes to mod function
	const auto stolenWriteRet =
		WriteProcessMemory(handle, (LPVOID)modFunction, createProcessBytes, 5, NULL);
	if (!stolenWriteRet) {
		return logAndExit("Failed writing stolen bytes to modding function");
	}

	// write shellcode to mod function
	const auto modWriteRet =
		WriteProcessMemory(handle, (LPVOID)(modFunction+5), &modShellcode[0], modShellcode.size(), NULL);
	if (!modWriteRet) {
		return logAndExit("Failed writing shellcode to modding function");
	}

	const auto returnJmpRet =
		WriteProcessMemory(handle, (LPVOID)(modFunction + 5 + modShellcode.size()),
			&returnJmpShellcode[0], returnJmpShellcode.size(), NULL);
	if (!returnJmpRet) {
		return logAndExit("Failed writing return shellcode to modding function");
	}

	// overwrite jmp
	const int target = createProcessAddress;
	const auto relativeJmp = modFunction - target - 5;

	std::vector<BYTE> hookShellcode = {
		0xE9,
		(BYTE)((relativeJmp >> (4 * 8)) & 0xFF),
		(BYTE)((relativeJmp >> (1 * 8)) & 0xFF),
		(BYTE)((relativeJmp >> (2 * 8)) & 0xFF),
		(BYTE)((relativeJmp >> (3 * 8)) & 0xFF),
	};

	const auto overwriteJmpRet =
		WriteProcessMemory(handle, (LPVOID)target, &hookShellcode[0], hookShellcode.size(), NULL);
	if (!overwriteJmpRet) {
		return logAndExit("Failed to hook");
	}

	// cleanup
	VirtualProtectEx(handle, (LPVOID)createProcessAddress, targetSize, old_CPW_Protect, &old_CPW_Protect);
}

BOOL unhook(HANDLE handle, LPVOID toUnhook) {
	return WriteProcessMemory(handle, toUnhook, &unhook_bytes, sizeof(unhook_bytes), NULL);
}

int logAndExit(std::string logMessage) {
	std::cout << logMessage << "\n";
	return 1;
}
