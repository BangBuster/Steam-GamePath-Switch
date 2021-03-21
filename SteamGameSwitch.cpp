#include <iostream>
#include <JustBanMe.h>
#include <JustBanMe.cpp>
#pragma warning(disable:4996)

int main()
{
	DWORD pid = GetProcessIDByName("steam.exe");
	std::cout << pid << "\n";
	getchar();
}

/*
* step 1: get module address
* step 2: apply offset or signature scan
* 
* step 3: save original bytes
* step 4: write string to codecave
* step 5: patch instruction to "mov eax, *string location*"
*/