#ifndef __UTILS_H__
#define __UTILS_H__

#include <Windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <fstream>
#include <wincrypt.h>
#include <list>
#include <locale>
#include <codecvt>
#include <compressapi.h>
#include <Rpc.h>
#include <wininet.h>
#include <sstream>
#include <psapi.h>
#include <comdef.h>
#include <tlhelp32.h>

#include <wtsapi32.h>


#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Cabinet.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment (lib, "wininet.lib")


using namespace std;


#ifndef MAX_NAME 
#define MAX_NAME 256
#endif


typedef struct ProcessEntity
{

	DWORD Pid = 0;
	DWORD PPID = 0;
	std::string Name;
	std::string Owner;
	std::string Arch;
};

class PS
{
private:
	static BOOL GetLogonFromToken(HANDLE hToken, _bstr_t& strUser, _bstr_t& strdomain)
	{
		DWORD dwSize = MAX_NAME;
		BOOL bSuccess = FALSE;
		DWORD dwLength = 0;
		strUser = "user";
		strdomain = "domain";
		PTOKEN_USER ptu = NULL;
		//Verify the parameter passed in is not NULL.
		if (NULL == hToken)
			goto Cleanup;

		if (!GetTokenInformation(
			hToken,         // handle to the access token
			TokenUser,    // get information about the token's groups 
			(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
			0,              // size of buffer
			&dwLength       // receives required buffer size
		))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				goto Cleanup;

			ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY, dwLength);

			if (ptu == NULL)
				goto Cleanup;
		}

		if (!GetTokenInformation(
			hToken,         // handle to the access token
			TokenUser,    // get information about the token's groups 
			(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
			dwLength,       // size of buffer
			&dwLength       // receives required buffer size
		))
		{
			goto Cleanup;
		}
		SID_NAME_USE SidType;
		char lpName[MAX_NAME];
		char lpDomain[MAX_NAME];

		strcpy_s(lpName, "defaultname");
		strcpy_s(lpDomain, "defaultdomain");

		if (!LookupAccountSidA(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
		{
		}
		else
		{
			strUser = lpName;
			strdomain = lpDomain;
			bSuccess = TRUE;
		}

	Cleanup:

		if (ptu != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
		return bSuccess;
	}




	static HRESULT GetUserFromProcess(const DWORD procId, _bstr_t& strUser, _bstr_t& strdomain)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
		if (hProcess == NULL)
			return E_FAIL;
		HANDLE hToken = NULL;

		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		{
			CloseHandle(hProcess);
			return E_FAIL;
		}
		BOOL bres = GetLogonFromToken(hToken, strUser, strdomain);

		CloseHandle(hToken);
		CloseHandle(hProcess);
		return bres ? S_OK : E_FAIL;
	}



	static DWORD GetParentProcessId(DWORD pid)
	{
		DWORD retval = 0;


		HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32);



		if (Process32First(h, &pe)) {
			do {
				if (pe.th32ProcessID == pid) {

					retval = pe.th32ParentProcessID;
					break;
				}
			} while (Process32Next(h, &pe));
		}

		CloseHandle(h);



		return retval;
	}




	static BOOL IsWow64(HANDLE process)
	{
		BOOL bIsWow64 = FALSE;

		typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		LPFN_ISWOW64PROCESS fnIsWow64Process;
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

		if (NULL != fnIsWow64Process)
		{
			if (!fnIsWow64Process(process, &bIsWow64))
			{
				//handle error
			}
		}
		return bIsWow64;
	}

	static bool IsX86Process(HANDLE process)
	{
		SYSTEM_INFO systemInfo = { 0 };
		GetNativeSystemInfo(&systemInfo);

		// x86 environment
		if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			return true;

		// Check if the process is an x86 process that is running on x64 environment.
		// IsWow64 returns true if the process is an x86 process
		return IsWow64(process);
	}





	static string ToAsciiString(wstring ws)
	{
		std::string s(ws.begin(), ws.end());
		return s;
	}


	static string GetProcessArch(HANDLE hProcess)
	{
		string retval("x64");

		if (IsWow64(hProcess))
		{
			retval = string("Wow64 (x86 Process Running on an x64 Machine)");
		}

		if (IsX86Process(hProcess))
		{
			retval = string("x86");
		}

		return retval;
	}




	static string GetProcessArchProcessId(DWORD processID)
	{
		string retval("x64");


		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID); // | PROCESS_VM_READ

		if (INVALID_HANDLE_VALUE == hProcess)
		{
			goto done;
		}

		retval = GetProcessArch(hProcess);


	done:
		if (NULL != hProcess)
		{
			CloseHandle(hProcess);
			hProcess = INVALID_HANDLE_VALUE;
		}



		return retval;
	}


	static string GetProcessOwner(DWORD processId)
	{
		string retval("unknown_owner");
		_bstr_t strUser;
		_bstr_t strDomain;

		if (S_OK == GetUserFromProcess(processId, strUser, strDomain))
		{
			char szOwner[512];
			sprintf_s(szOwner, "%s\\%s", (char*)strDomain, (char*)strUser);
			retval = string(szOwner);
		}


		return retval;
	}

public:




	static list<ProcessEntity> GetProcessTable()
	{
		list<ProcessEntity> retval;



		WTS_PROCESS_INFOA* pWPIs = NULL;
		DWORD dwProcCount = 0;
		if (WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount))
		{
			//Go through all processes retrieved
			for (DWORD i = 0; i < dwProcCount; i++)
			{
				string processName(pWPIs[i].pProcessName);
				DWORD processId = pWPIs[i].ProcessId;

				string sProcessName = processName;// ToAsciiString(processName);

				ProcessEntity processList;
				processList.Name = sProcessName;
				processList.Pid = processId;
				processList.PPID = GetParentProcessId(processId);
				processList.Owner = GetProcessOwner(processId);
				processList.Arch = GetProcessArchProcessId(processId);
				retval.push_back(processList);
			}
		}

		//Free memory
		if (pWPIs)
		{
			WTSFreeMemory(pWPIs);
			pWPIs = NULL;
		}

	done:


		return retval;
	}



};


class IO
{
public:

	static string GetComputerNameZ()
	{
		string retval("");
		char  szBuffer[512];
		DWORD  dwBufferLength = 512;

		memset(szBuffer, 0, dwBufferLength);
		if (GetComputerNameA(szBuffer, &dwBufferLength))
		{
			retval = string(szBuffer);
		}

		return retval;
	}

	static string GetUserNameCAT()
	{

		char szUserName[512];
		DWORD dwUserNameLength = 512;
		GetUserNameA(szUserName, &dwUserNameLength);

		string userName(szUserName);

		return userName;
	}

	static string GetTempPathCAT()
	{

		char szBuffer[512];
		DWORD dwBufferLength = sizeof(szBuffer);
		memset(szBuffer, 0, dwBufferLength);

		GetTempPathA(dwBufferLength, szBuffer);

		return string(szBuffer);
	}

	static bool FileExists(string fileName)
	{
		bool retval = true;

		if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(fileName.c_str()))
		{
			if (GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				retval = false;
			}
		}

		return retval;
	}

	static string ReadAllText(const char* name)
	{
		string retval("");
		vector<BYTE> bytes = ReadAllBytes(name);

		DWORD dwBufferLength = 1 + (DWORD)bytes.size();
		char* psz = new char[dwBufferLength];

		memset(psz, 0, dwBufferLength);

		for (DWORD dwIndex = 0; dwIndex < bytes.size(); dwIndex++)
		{
			psz[dwIndex] = bytes[dwIndex];
		}

		retval = string(psz);
		delete[] psz;
		psz = NULL;

		return retval;
	}

	static void WriteAllText(const char* name, string s)
	{
		DWORD dwBufferLength = 1 + (DWORD)s.length();
		char* psz = new char[dwBufferLength];

		memset(psz, 0, dwBufferLength);

		strcpy_s(psz, dwBufferLength, s.c_str());

		vector<BYTE> bytes;

		for (DWORD dwIndex = 0; dwIndex < dwBufferLength; dwIndex++)
		{
			bytes.push_back((BYTE)psz[dwIndex]);
		}


		WriteAllBytes(name, bytes);

		if (NULL != psz)
		{
			delete[] psz;
			psz = NULL;
		}
	}



	static void WriteAllBytes(const char* name, vector<BYTE> bytes)
	{


		DWORD dwBytesWritten = 0;
		BYTE* pvBuffer = new BYTE[bytes.size()];
		DWORD dwBufferLength = (DWORD)bytes.size();



		for (DWORD dwIndex = 0; dwIndex < bytes.size(); dwIndex++)
		{
			pvBuffer[dwIndex] = bytes[dwIndex];
		}


		HANDLE hFile = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (INVALID_HANDLE_VALUE == hFile)
		{
			cerr << "ERROR: CreateFile failed." << endl;
			goto done;
		}


		if (!WriteFile(hFile, pvBuffer, dwBufferLength, &dwBytesWritten, NULL))
		{
			cerr << "ERROR: WriteFile failed. gle=" << GetLastError() << endl;
		}




	done:

		if (NULL != pvBuffer)
		{
			delete[] pvBuffer;
			pvBuffer = NULL;
		}
		if (INVALID_HANDLE_VALUE != hFile)
		{
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
	}

	static vector<BYTE> ReadAllBytes(const char* name)
	{
		vector<BYTE> retval;
		DWORD dwFileSize = (DWORD)IO::FileSize(name);


		BYTE* pvBuffer = new BYTE[dwFileSize];
		DWORD dwBytesRead = 0;

		HANDLE hFile = CreateFileA(name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (INVALID_HANDLE_VALUE == hFile)
		{
			goto done;
		}


		if (ReadFile(hFile, pvBuffer, dwFileSize, &dwBytesRead, NULL))
		{

			retval.resize(dwBytesRead);

			if (dwBytesRead == dwFileSize)
			{
				for (DWORD dwIndex = 0; dwIndex < dwBytesRead; dwIndex++)
				{
					retval[dwIndex] = pvBuffer[dwIndex];
				}
			}
		}
		else
		{
			cerr << "ReadFile failed gle=" << GetLastError() << endl;
		}


	done:

		if (NULL != pvBuffer)
		{
			delete[] pvBuffer;
			pvBuffer = NULL;
		}

		if (INVALID_HANDLE_VALUE != hFile)
		{
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}

		return retval;
	}


	static LONGLONG FileSize(const char* name)
	{
		LONGLONG retval = 0;
		LARGE_INTEGER size;
		HANDLE hFile = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (INVALID_HANDLE_VALUE == hFile)
		{
			goto done;
		}


		if (!GetFileSizeEx(hFile, &size))
		{
			goto done;
		}


		retval = size.QuadPart;

	done:

		if (INVALID_HANDLE_VALUE != hFile)
		{
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}

		return retval;

	}



};

class Log
{
public:


	static void Write(string message, DWORD dwMessage)
	{
		std::ofstream fout;

		fout.open("c:\\Public\\gengar.txt", std::ios_base::app);
		if (fout.is_open())
		{
			fout << message << " " << dwMessage << endl;
			fout.close();
		}
	}

	static void Write(string message)
	{
		std::ofstream fout;

		fout.open("c:\\Public\\gengar.txt", std::ios_base::app);
		if (fout.is_open())
		{
			fout << message << endl;
			fout.close();
		}
	}



	static void Write(string message, string s)
	{
		std::ofstream fout;

		fout.open("c:\\Public\\gengar.txt", std::ios_base::app);
		if (fout.is_open())
		{
			fout << message << " " << s << endl;
			fout.close();
		}

	}



	static void Write(string message, string s, string s1)
	{
		std::ofstream fout;

		fout.open("c:\\Public\\gengar.txt", std::ios_base::app);
		if (fout.is_open())
		{
			fout << message << " " << s << " " << s1 << endl;
			fout.close();
		}

	}

};



class StringUtils
{
public:


	static void replaceAll(string& s, const string& search, const string& replace)
	{
		for (size_t pos = 0; ; pos += replace.length())
		{
			// Locate the substring to replace
			pos = s.find(search, pos);
			if (pos == string::npos) break;
			// Replace by erasing and inserting
			s.erase(pos, search.length());
			s.insert(pos, replace);
		}
	}


	static BOOL StartsWith(string s, string startsWith)
	{
		BOOL retval = false;

		if (s.rfind(startsWith, 0) == 0) {
			retval = TRUE;
		}

		return retval;
	}

	static vector<string> Split(string& str, string& delims)
	{
		vector<string> retval;
		std::size_t current, previous = 0;
		current = str.find_first_of(delims);

		while (current != std::string::npos)
		{
			retval.push_back(str.substr(previous, current - previous));
			previous = current + 1;
			current = str.find_first_of(delims, previous);
		}
		retval.push_back(str.substr(previous, current - previous));

		return retval;
	}

	static vector<string> SplitRemoteEmptyElements(string& str, string& delims)
	{
		vector<string> retval;

		vector<string> tmp = Split(str, delims);

		for (vector<string>::iterator i = tmp.begin(); i != tmp.end(); i++)
		{
			string s = *i;

			if (strlen(s.c_str()) > 0)
			{
				retval.push_back(s);
			}
		}

		return retval;
	}

};


class WebClient
{
private:
	BOOL m_bOK = TRUE;
	string m_RequestHeaders;
	string m_UserAgent;
	HINTERNET m_hInternet;
	HINTERNET m_hConnection;
	HINTERNET m_hRequest;



public:

	WebClient()
	{
		m_RequestHeaders = string("Authorization: Basic VVNDb3VydHNUZWxlbWV0cnk6ZDcwMWRjN2ItYmZhZS00YzgwLWE4MTYtZjIwZTFmMzU2ZGZj\r\nAccept: application/vnd.github.v3+json\r\n");
		m_UserAgent = "USCourtsTelemetry";
		m_hInternet = NULL;
		m_hConnection = NULL;
		m_hRequest = NULL;



		m_hInternet = InternetOpenA(m_UserAgent.c_str(),
			INTERNET_OPEN_TYPE_PRECONFIG,
			NULL,
			NULL, 0);

		if (NULL == m_hInternet)
		{
			cerr << "ERROR: InternetOpenA failed. gle=" << GetLastError() << endl;
			m_bOK = FALSE;
		}








	}

	~WebClient()
	{
		if (NULL != m_hRequest)
		{
			InternetCloseHandle(m_hRequest);
			m_hRequest = NULL;
		}



		if (NULL != m_hInternet)
		{
			InternetCloseHandle(m_hInternet);
			m_hInternet = NULL;
		}
	}

	string DownloadString(string server, string url)
	{
		string retval("");



		if (m_bOK)
		{
			m_hConnection = InternetConnectA(m_hInternet,
				server.c_str(),
				443,
				NULL, NULL,
				INTERNET_SERVICE_HTTP, 0, 0);

			if (NULL == m_hConnection)
			{
				cerr << "ERROR: InternetConnectA failed. gle=" << GetLastError() << endl;
				m_bOK = false;
			}
		}




		if (m_bOK)
		{
			DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_SECURE;


			m_hRequest = HttpOpenRequestA(m_hConnection, "GET",
				url.c_str(),
				NULL, NULL, NULL,
				flags, 0);

			if (NULL == m_hRequest)
			{
				cerr << "ERROR: HttpOpenRequestA failed. gle=" << GetLastError() << endl;
				m_bOK = FALSE;
			}
		}

		if (m_bOK)
		{
			DWORD reqFlags = 0;
			DWORD dwBuffLen = sizeof(reqFlags);

			InternetQueryOption(m_hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&reqFlags, &dwBuffLen);
			reqFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
			InternetSetOption(m_hRequest, INTERNET_OPTION_SECURITY_FLAGS, &reqFlags, sizeof(reqFlags));
		}


		if (m_bOK)
		{
			if (!HttpSendRequestA(m_hRequest, m_RequestHeaders.c_str(), (DWORD)m_RequestHeaders.length(), NULL, 0))
			{
				cerr << "ERROR: HttpSendRequestA failed. gle=" << GetLastError() << endl;
				m_bOK = FALSE;
			}
		}

		if (m_bOK)
		{
			DWORD dwBytesRead = 0;
			char buffer[1024];
			std::string returnData = "";

			while (InternetReadFile(m_hRequest, buffer, sizeof(buffer), &dwBytesRead) == TRUE && dwBytesRead != 0)
			{
				returnData.append(buffer, dwBytesRead);
				if (dwBytesRead == 0)
					break;
			}

			retval = returnData;
		}



		if (NULL != m_hRequest)
		{
			InternetCloseHandle(m_hRequest);
		}

		if (NULL != m_hConnection)
		{
			InternetCloseHandle(m_hConnection);
		}

		return retval;
	}



	string UploadString(string server, string url, string method, BYTE* pvData, DWORD dwDataLength)
	{
		string retval("");



		if (m_bOK)
		{
			m_hConnection = InternetConnectA(m_hInternet,
				server.c_str(),
				443,
				NULL, NULL,
				INTERNET_SERVICE_HTTP, 0, 0);

			if (NULL == m_hConnection)
			{
				cerr << "ERROR: InternetConnectA failed. gle=" << GetLastError() << endl;
				m_bOK = false;
			}
		}




		if (m_bOK)
		{
			DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_SECURE;


			m_hRequest = HttpOpenRequestA(m_hConnection, method.c_str(),
				url.c_str(),
				NULL, NULL, NULL,
				flags, 0);

			if (NULL == m_hRequest)
			{
				cerr << "ERROR: HttpOpenRequestA failed. gle=" << GetLastError() << endl;
				m_bOK = FALSE;
			}
		}

		if (m_bOK)
		{
			DWORD reqFlags = 0;
			DWORD dwBuffLen = sizeof(reqFlags);

			InternetQueryOption(m_hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&reqFlags, &dwBuffLen);
			reqFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
			InternetSetOption(m_hRequest, INTERNET_OPTION_SECURITY_FLAGS, &reqFlags, sizeof(reqFlags));
		}


		if (m_bOK)
		{
			if (!HttpSendRequestA(m_hRequest, m_RequestHeaders.c_str(), (DWORD)m_RequestHeaders.length(), pvData, dwDataLength))
			{
				cerr << "ERROR: HttpSendRequestA failed. gle=" << GetLastError() << endl;
				m_bOK = FALSE;
			}
		}

		if (m_bOK)
		{
			DWORD dwBytesRead = 0;
			char buffer[1024];
			std::string returnData = "";

			while (InternetReadFile(m_hRequest, buffer, sizeof(buffer), &dwBytesRead) == TRUE && dwBytesRead != 0)
			{
				returnData.append(buffer, dwBytesRead);
				if (dwBytesRead == 0)
					break;
			}

			retval = returnData;
		}



		if (NULL != m_hRequest)
		{
			InternetCloseHandle(m_hRequest);
		}

		if (NULL != m_hConnection)
		{
			InternetCloseHandle(m_hConnection);
		}

		return retval;
	}



};




class Convert
{
public:


	static string VectorToString(vector<BYTE> bytes)
	{
		string retval("");
		char* psz = new char[bytes.size()];

		memset(psz, 0, bytes.size());

		for (DWORD dwIndex = 0; dwIndex < bytes.size(); dwIndex++)
		{
			psz[dwIndex] = bytes[dwIndex];
		}

		retval = string(psz);

		delete[] psz;
		psz = NULL;


		return retval;
	}

	static vector<BYTE> StringToVector(string s)
	{
		vector<BYTE> retval;
		char* psz = new char[s.size() + 1];
		DWORD dwLength = 1 + s.size();

		memset(psz, 0, dwLength);

		strcpy_s(psz, dwLength, s.c_str());

		for (DWORD dwIndex = 0; dwIndex < dwLength; dwIndex++)
		{
			retval.push_back(psz[dwIndex]);
		}

		return retval;
	}

	static std::wstring s2ws(const std::string& str)
	{
		using convert_typeX = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_typeX, wchar_t> converterX;

		return converterX.from_bytes(str);
	}

	static std::string ws2s(const std::wstring& wstr)
	{
		using convert_typeX = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_typeX, wchar_t> converterX;

		return converterX.to_bytes(wstr);
	}





	static tuple<BYTE*, DWORD> VectorToByteArray(vector<BYTE> bytes)
	{
		DWORD dwBufferLength = (DWORD)bytes.size();
		BYTE* pBytes = new BYTE[dwBufferLength];

		for (DWORD dwIndex = 0; dwIndex < bytes.size(); dwIndex++)
		{
			pBytes[dwIndex] = bytes[dwIndex];
		}

		return tuple<BYTE*, DWORD>(pBytes, dwBufferLength);
	}

	static vector<BYTE> ByteArrayToVector(BYTE* bytes, DWORD dwBufferLength)
	{
		vector<BYTE> retval;

		retval.resize(dwBufferLength);

		for (DWORD dwIndex = 0; dwIndex < dwBufferLength; dwIndex++)
		{
			retval.push_back(bytes[dwIndex]);
		}

		return retval;
	}



};


class Util
{
private:
	static list<tuple<BYTE*, DWORD>> ChunkifyBuffer(BYTE* pvBuffer, DWORD dwBufferLength, DWORD dwChunkSize)
	{
		list<tuple<BYTE*, DWORD>> retval;

		if (dwBufferLength <= dwChunkSize)
		{
			retval.push_back(tuple<BYTE*, DWORD>(pvBuffer, dwBufferLength));
		}
		else
		{
			DWORD dwNumberOfChunks = (DWORD)(dwBufferLength / dwChunkSize);
			DWORD dwRemainderSize = dwBufferLength - (dwNumberOfChunks * dwChunkSize);



			BYTE* pCurrentChunk = pvBuffer;
			for (DWORD dwChunkIndex = 0; dwChunkIndex < dwNumberOfChunks; dwChunkIndex++)
			{
				tuple<BYTE*, DWORD> chunk(pCurrentChunk, dwChunkSize);
				retval.push_back(chunk);
				pCurrentChunk += dwChunkSize;
			}

			tuple<BYTE*, DWORD> lastChunk(pCurrentChunk, dwRemainderSize);

			retval.push_back(lastChunk);


		}



		return retval;
	}
public:




	static vector<string> Chunkify(string s, DWORD dwChunkSize)
	{
		vector<string> retval;
		DWORD dwBufferLength = 1 + (DWORD)s.size();
		char* buffer = new char[dwBufferLength];

		strcpy_s(buffer, dwBufferLength, s.c_str());

		list<tuple<BYTE*, DWORD>> vad = ChunkifyBuffer((BYTE*)buffer, dwBufferLength, dwChunkSize);




		for (list<tuple<BYTE*, DWORD>>::iterator i = vad.begin(); i != vad.end(); i++)
		{
			tuple<BYTE*, DWORD> t = (*i);
			char* psz = (char*)std::get<0>(t);
			DWORD dwLength = std::get<1>(t);

			char* p = new char[1 + dwLength];
			memset(p, 0, 1 + dwLength);
			strncpy_s(p, 1 + dwLength, psz, dwLength);
			retval.push_back(string(p));
			delete[] p;
			//printf("%.*s\n", dwLength, psz);
		}



		delete[] buffer;

		return retval;
	}



	static string NewGuid()
	{
		string retval("00000000-0000-0000-0000-000000000000");


		UUID uuid;
		RPC_STATUS ret_val = ::UuidCreate(&uuid);

		if (ret_val == RPC_S_OK)
		{
			// convert UUID to LPWSTR
			WCHAR* wszUuid = NULL;
			::UuidToStringW(&uuid, (RPC_WSTR*)&wszUuid);
			if (wszUuid != NULL)
			{
				wstring ws(wszUuid);

				retval = Convert::ws2s(ws);

				::RpcStringFreeW((RPC_WSTR*)&wszUuid);
				wszUuid = NULL;
			}

		}

		return retval;
	}

	static BOOL StartsWith(string s, string startsWith)
	{
		BOOL retval = false;


		if (s.rfind(startsWith, 0) == 0) {
			retval = TRUE;
		}

		return retval;
	}
};






class Base64Util
{
private:
	bool is_base64(BYTE c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}


	std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";
public:

	string EncodeString(string toEncode)
	{
		string retval("");


		const BYTE* bytes = (const BYTE*)toEncode.c_str();
		DWORD dwBytes = (DWORD)strlen(toEncode.c_str());



		char* pchB64 = NULL;
		DWORD dwB64 = 0;

		BOOL cat = CryptBinaryToStringA(
			bytes,
			dwBytes,
			CRYPT_STRING_BASE64,
			NULL,
			&dwB64
		);


		pchB64 = new char[dwB64 + 1];
		memset(pchB64, 0, dwB64 + 1);

		CryptBinaryToStringA(
			bytes,
			dwBytes,
			CRYPT_STRING_BASE64,
			pchB64,
			&dwB64
		);

		retval = string(pchB64);

		delete[] pchB64;
		pchB64 = NULL;



		return retval;
	}

	string DecodeStringToString(string encoded)
	{
		string retval("");


		vector<BYTE> bytes = DecodeToByteVector(encoded);

		DWORD dwSize = 1 + bytes.size();
		char* psz = new char[dwSize];

		memset(psz, 0, dwSize);

		for (int x = 0; x < bytes.size(); x++)
		{
			psz[x] = bytes[x];
		}

		retval = string(psz);

		delete[] psz;
		psz = NULL;

		return retval;
	}




	std::vector<BYTE> DecodeToByteVector(std::string const& encoded_string) {
		int in_len = encoded_string.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		BYTE char_array_4[4], char_array_3[3];
		std::vector<BYTE> ret;

		while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
			char_array_4[i++] = encoded_string[in_]; in_++;
			if (i == 4) {
				for (i = 0; i < 4; i++)
					char_array_4[i] = base64_chars.find(char_array_4[i]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (i = 0; (i < 3); i++)
					ret.push_back(char_array_3[i]);
				i = 0;
			}
		}

		if (i) {
			for (j = i; j < 4; j++)
				char_array_4[j] = 0;

			for (j = 0; j < 4; j++)
				char_array_4[j] = base64_chars.find(char_array_4[j]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
		}

		return ret;
	}




	std::string EncodeByteArrayToString(BYTE const* buf, unsigned int bufLen) {
		std::string ret;
		int i = 0;
		int j = 0;
		BYTE char_array_3[3];
		BYTE char_array_4[4];

		while (bufLen--) {
			char_array_3[i++] = *(buf++);
			if (i == 3) {
				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (i = 0; (i < 4); i++)
					ret += base64_chars[char_array_4[i]];
				i = 0;
			}
		}

		if (i)
		{
			for (j = i; j < 3; j++)
				char_array_3[j] = '\0';

			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (j = 0; (j < i + 1); j++)
				ret += base64_chars[char_array_4[j]];

			while ((i++ < 3))
				ret += '=';
		}

		return ret;
	}

	std::string EncodeByteVectorToString(vector<BYTE> bytes)
	{
		string retval("");


		tuple<BYTE*, DWORD> tuple = Convert::VectorToByteArray(bytes);
		BYTE* dllBytes = std::get<0>(tuple);
		DWORD dllBytesLength = std::get<1>(tuple);

		retval = EncodeByteArrayToString(dllBytes, dllBytesLength);


		return retval;
	}


};

class HashUtil
{
private:
	enum HashType
	{
		HashSha1, HashMd5, HashSha256
	};


	static string GetHashTextP(const void* data, const size_t data_size, HashType hashType)
	{
		HCRYPTPROV hProv = NULL;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
			return "";
		}

		BOOL hash_ok = FALSE;
		HCRYPTPROV hHash = NULL;
		switch (hashType) {
		case HashSha1: hash_ok = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash); break;
		case HashMd5: hash_ok = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash); break;
		case HashSha256: hash_ok = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash); break;
		}

		if (!hash_ok) {
			CryptReleaseContext(hProv, 0);
			return "";
		}

		if (!CryptHashData(hHash, static_cast<const BYTE*>(data), data_size, 0)) {
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return "";
		}

		DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0)) {
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return "";
		}

		std::vector<BYTE> buffer(cbHashSize);
		if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&buffer[0]), &cbHashSize, 0)) {
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return "";
		}


		std::ostringstream oss;

		for (std::vector<BYTE>::const_iterator iter = buffer.begin(); iter != buffer.end(); ++iter) {
			oss.fill('0');
			oss.width(2);
			oss << std::hex << static_cast<const int>(*iter);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return oss.str();
	}

public:

	static string CalculateHash(string s)
	{
		HashType hashType = HashSha256;
		return GetHashTextP(s.c_str(), s.size(), hashType);
	}


};


class RsaUtil
{
private:
	const DWORD RSA2048BIT_KEY = 0x8000000;

	BYTE* publicKeyBlob = NULL;
	DWORD dwPublicKeyBlobLength = 0;

	BYTE* privateKeyBlob = NULL;
	DWORD dwPrivateKeyBlobLength = 0;
public:

	vector<BYTE> Decrypt(string b64CipherText)
	{
		vector<BYTE> retval;
		HCRYPTPROV hProv;
		HCRYPTKEY hKey;
		Base64Util base64;
		vector<BYTE> cipherText = base64.DecodeToByteVector(b64CipherText);
		DWORD dwCipherTextLength = (DWORD)cipherText.size();
		BYTE* cipherTextBytes = new BYTE[dwCipherTextLength];

		DWORD dwPlainTextBytesLength = (DWORD)cipherText.size();
		BYTE* plainTextBytes = NULL;


		for (DWORD x = 0; x < dwCipherTextLength; x++)
		{
			cipherTextBytes[x] = cipherText[x];
		}


		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			Log::Write("ERROR: CryptAcquireContext failed.");
			goto done;
		}


		if (!CryptImportKey(hProv, privateKeyBlob, dwPrivateKeyBlobLength, 0, CRYPT_EXPORTABLE, &hKey))
		{
			Log::Write("ERROR: CryptImportKey (1) failed gle=", GetLastError());
			goto done;
		}


		plainTextBytes = new BYTE[dwPlainTextBytesLength];


		SecureZeroMemory(plainTextBytes, dwPlainTextBytesLength * sizeof(unsigned char));

		memcpy_s(plainTextBytes, dwPlainTextBytesLength, cipherTextBytes, dwPlainTextBytesLength);

		delete[](cipherTextBytes);
		cipherTextBytes = NULL;

		//	len = decodedLen;
		if (!CryptDecrypt(hKey, 0, TRUE, 0, plainTextBytes, &dwPlainTextBytesLength))
		{
			Log::Write("ERROR: CryptDecrypt failed gle=", GetLastError());
			goto done;
		}

		Log::Write("plainTextBytes=", (char*)plainTextBytes);

		for (DWORD dwIndex = 0; dwIndex < dwPlainTextBytesLength; dwIndex++)
		{
			retval.push_back(plainTextBytes[dwIndex]);
		}


	done:
		if (hKey)
		{
			CryptDestroyKey(hKey);
		}

		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}

		return retval;
	}

	string EncryptString(string plaintext)
	{
		BYTE* plaintextBytes = (BYTE*)plaintext.c_str();
		DWORD dwPlainTextBytesLength = 1 + (DWORD)strlen(plaintext.c_str());

		return Encrypt(plaintextBytes, dwPlainTextBytesLength);
	}


	string Encrypt(BYTE* plaintextBytes, DWORD dwPlaintextBytesLength)
	{
		string retval("");
		HCRYPTPROV hProv;
		HCRYPTKEY hKey;

		DWORD dwCipherTextLength = dwPlaintextBytesLength + 1;
		BYTE* cipherTextBytes = NULL;
		Base64Util base64;

		DWORD len = 0;
		DWORD pLen = 0;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			Log::Write("ERROR: CryptAcquireContext failed.");
			goto done;
		}


		if (!CryptImportKey(hProv, publicKeyBlob, dwPublicKeyBlobLength, 0, CRYPT_EXPORTABLE, &hKey))
		{
			Log::Write("ERROR: CryptImportKey (2) failed gle=", GetLastError());
			//	Log::Write("publicKey=", )
			goto done;
		}


		if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dwCipherTextLength, 0))
		{
			Log::Write("ERROR: CryptEncrypt(1) failed.");
			goto done;
		}


		if (NULL == (cipherTextBytes = (BYTE*)malloc(dwCipherTextLength)))
		{
			Log::Write("ERROR: insufficient memory.");
			goto done;
		}


		SecureZeroMemory(cipherTextBytes, dwCipherTextLength * sizeof(unsigned char));

		memcpy_s(cipherTextBytes, dwCipherTextLength, plaintextBytes, dwPlaintextBytesLength + 1);

		len = dwPlaintextBytesLength + 1;


		if (!CryptEncrypt(hKey, 0, TRUE, 0, cipherTextBytes, &len, dwCipherTextLength))
		{
			Log::Write("ERROR: CryptEncrypt(2) failed. gle=", GetLastError());
			goto done;
		}

		retval = base64.EncodeByteArrayToString(cipherTextBytes, dwCipherTextLength);

	done:


		if (hKey)
		{
			CryptDestroyKey(hKey);
		}

		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}


		return retval;
	}









	void SetPublicKeyAsBase64String(string b64PublicKey)
	{
		Base64Util u;
		vector<BYTE> vbytes = u.DecodeToByteVector(b64PublicKey);

		dwPublicKeyBlobLength = (DWORD)vbytes.size();
		publicKeyBlob = new BYTE[dwPublicKeyBlobLength];

		for (DWORD x = 0; x < dwPublicKeyBlobLength; x++)
		{
			publicKeyBlob[x] = vbytes[x];
		}
	}


	void SetPrivateKeyAsBase64String(string b64PrivateKey)
	{
		Base64Util u;
		vector<BYTE> vbytes = u.DecodeToByteVector(b64PrivateKey);

		dwPrivateKeyBlobLength = (DWORD)vbytes.size();
		privateKeyBlob = new BYTE[dwPrivateKeyBlobLength];

		for (DWORD x = 0; x < dwPrivateKeyBlobLength; x++)
		{
			privateKeyBlob[x] = vbytes[x];
		}
	}


	string GetPublicKeyAsBase64String()
	{
		Base64Util u;
		return u.EncodeByteArrayToString(publicKeyBlob, dwPublicKeyBlobLength);
	}


	string GetPrivateKeyAsBase64String()
	{
		Base64Util u;
		return u.EncodeByteArrayToString(privateKeyBlob, dwPrivateKeyBlobLength);
	}

	void GenerateKeyPair()
	{
		HCRYPTPROV hProv;
		HCRYPTKEY hKey;



		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
			cerr << "ERROR: CryptAcquireContext failed." << endl;
		}




		if (CryptGenKey(hProv, AT_KEYEXCHANGE, RSA2048BIT_KEY | CRYPT_EXPORTABLE, &hKey))
		{
			cout << "SUCCESS: CryptGenKey" << endl;
		}
		else
		{
			cerr << "ERROR: CryptGenKey failed." << endl;
		}


		//
		// export the public key
		//

		if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyBlobLength))
		{
			cerr << "ERROR: CryptExportKey failed." << endl;
		}
		else
		{
			cout << "SUCCESS: CryptExportKey succeeded." << endl;
		}



		if (publicKeyBlob = (BYTE*)malloc(dwPublicKeyBlobLength))
		{
			cout << "SUCCESS: malloced public key." << endl;
		}
		else
		{
			cerr << "ERROR: failed to allocate memory for public key." << endl;
		}




		if (CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, publicKeyBlob, &dwPublicKeyBlobLength))
		{
			printf("Contents have been written to the BLOB dwPublicKeyBlobLength=%d\n", dwPublicKeyBlobLength);
		}
		else
		{
			printf("Error during CryptExportKey.");
		}







		//
		 // export the PRIVATE key
		 //

		if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwPrivateKeyBlobLength))
		{
			cerr << "ERROR: CryptExportKey failed." << endl;
		}
		else
		{
			cout << "SUCCESS: CryptExportKey succeeded." << endl;
		}



		if (privateKeyBlob = (BYTE*)malloc(dwPrivateKeyBlobLength))
		{
			cout << "SUCCESS: malloced public key." << endl;
		}
		else
		{
			cerr << "ERROR: failed to allocate memory for public key." << endl;
		}




		if (CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, privateKeyBlob, &dwPrivateKeyBlobLength))
		{
			printf("Contents have been written to the BLOB (exported private key). \n");
		}
		else
		{
			printf("Error during CryptExportKey.");
		}









		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}





	}

};

class AesUtil
{
private:
	const DWORD KEYLENGTH = 0x00800000;
	const DWORD ENCRYPT_ALGORITHM = CALG_RC4;
	const DWORD ENCRYPT_BLOCK_SIZE = 8;

public:

	string DecryptToString(string password, string b64CipherText)
	{
		string retval("cat");
		vector<BYTE> vPlainText = DecryptToVector(password, b64CipherText);
		DWORD dwPlainTextLength = 1 + (DWORD)vPlainText.size();

		char* pszPlainText = new char[dwPlainTextLength];
		memset(pszPlainText, 0, dwPlainTextLength);

		for (DWORD dwIndex = 0; dwIndex < vPlainText.size(); dwIndex++)
		{
			pszPlainText[dwIndex] = vPlainText[dwIndex];
		}

		retval = string(pszPlainText);
		delete[] pszPlainText;
		pszPlainText = NULL;

		return retval;
	}


	vector<BYTE> DecryptToVector(string password, string b64CipherText)
	{
		vector<BYTE> retval;
		HCRYPTPROV hCryptProv = NULL;
		HCRYPTHASH hHash = NULL;
		char szPassword[512];
		DWORD dwPasswordLength = 0;
		HCRYPTKEY hKey = NULL;

		//
		//
		//
		DWORD dwCipherTextBytesLength = 0;
		BYTE* pCipherTextBytes = NULL;
		Base64Util base64;

		//
		// convert to encrypted byte array for future processing
		//
		vector<BYTE> vCipherTextBytes = base64.DecodeToByteVector(b64CipherText);
		dwCipherTextBytesLength = (DWORD)vCipherTextBytes.size();
		pCipherTextBytes = new BYTE[dwCipherTextBytesLength];

		for (DWORD dwIndex = 0; dwIndex < dwCipherTextBytesLength; dwIndex++)
		{
			pCipherTextBytes[dwIndex] = vCipherTextBytes[dwIndex];
		}


		//
		// prepare the password
		//
		strcpy_s(szPassword, sizeof(szPassword), password.c_str());

		if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			cerr << "ERROR: CryptAcquireContext failed." << endl;
			goto done;
		}


		if (CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash))
		{
			cout << "SUCCESS: CryptCreateHash succeeded." << endl;
		}
		else
		{
			cerr << "ERROR: CryptCreateHash failed." << endl;
			goto done;
		}


		if (CryptHashData(hHash, (BYTE*)szPassword, lstrlenA(szPassword), 0))
		{
			cout << "SUCCESS: CryptHashData" << endl;
		}
		else
		{
			cerr << "ERROR: CryptHashData failed." << endl;
			goto done;
		}

		if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey))
		{
			cerr << "ERROR: CryptDeriveKey failed." << endl;
			goto done;
		}
		else
		{
			cout << "SUCCESS: CryptDeriveKey succeeded." << endl;
		}




		if (CryptDecrypt(hKey, NULL, TRUE, 0, pCipherTextBytes, &dwCipherTextBytesLength))
		{
			cout << "SUCCESS: CryptDecrypt worked dwCipherTextBytesLength=" << dwCipherTextBytesLength << endl;

			BYTE* plaintextBytes = new BYTE[dwCipherTextBytesLength];
			memset(plaintextBytes, 0, dwCipherTextBytesLength);
			memcpy(plaintextBytes, pCipherTextBytes, dwCipherTextBytesLength);


			for (DWORD dwIndex = 0; dwIndex < dwCipherTextBytesLength; dwIndex++)
			{
				retval.push_back(plaintextBytes[dwIndex]);
			}

		}
		else
		{
			cerr << "ERROR: CryptDecrypt failed. gle=" << GetLastError() << endl;
		}


		/*


		dwCount = dwPlaintextBytesLength;

		if (!CryptEncrypt(hKey, NULL, true, 0, pBuffer, &dwCount, dwBufferLength))
		{
			cerr << "ERROR: CryptEncrypt failed. gle=" << GetLastError() << endl;
			goto done;
		}
		else
		{
			cout << "SUCCESS: CryptEncrypt succeeded. dwCount=" << dwCount << endl;



			Base64Util b64;
			retval = b64.EncodeByteArrayToString(pBuffer, dwCount);
			cout << "!!!" << retval << endl;

		}
		*/



















	done:

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
			{
				cerr << "ERROR: CryptDestroyHash failed." << endl;
			}

			hHash = NULL;
		}


		if (hCryptProv)
		{
			if (!(CryptReleaseContext(hCryptProv, 0)))
			{
				cerr << "ERROR: CryptReleaseContext failed." << endl;
			}
		}


		return retval;
	}




	string EncryptVectorToBase64String(string password, vector<BYTE> vPlainText)
	{
		std::tuple<BYTE*, DWORD> t = Convert::VectorToByteArray(vPlainText);
		BYTE* plaintextBytes = std::get<0>(t);
		DWORD dwPlaintextBytesLength = std::get<1>(t);

		string retval = EncryptToBase64String(password, plaintextBytes, dwPlaintextBytesLength);
		return retval;
	}




	string EncryptToBase64String(string password, BYTE* plaintextBytes, DWORD dwPlaintextBytesLength)
	{
		string retval("cat");
		HCRYPTPROV hCryptProv = NULL;
		HCRYPTHASH hHash = NULL;
		char szPassword[512];
		DWORD dwPasswordLength = 0;
		HCRYPTKEY hKey = NULL;
		DWORD dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;


		DWORD dwBufferLength = dwPlaintextBytesLength;
		BYTE* pBuffer = (BYTE*)malloc(dwBufferLength);
		DWORD dwCount = 0;

		memcpy(pBuffer, plaintextBytes, dwBufferLength);


		strcpy_s(szPassword, sizeof(szPassword), password.c_str());

		if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			cerr << "ERROR: CryptAcquireContext failed." << endl;
			goto done;
		}


		if (CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash))
		{
			cout << "SUCCESS: CryptCreateHash succeeded." << endl;
		}
		else
		{
			cerr << "ERROR: CryptCreateHash failed." << endl;
			goto done;
		}


		if (CryptHashData(hHash, (BYTE*)szPassword, lstrlenA(szPassword), 0))
		{
			cout << "SUCCESS: CryptHashData" << endl;
		}
		else
		{
			cerr << "ERROR: CryptHashData failed." << endl;
			goto done;
		}

		if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey))
		{
			cerr << "ERROR: CryptDeriveKey failed." << endl;
			goto done;
		}
		else
		{
			cout << "SUCCESS: CryptDeriveKey succeeded." << endl;
		}








		dwCount = dwPlaintextBytesLength;

		if (!CryptEncrypt(hKey, NULL, true, 0, pBuffer, &dwCount, dwBufferLength))
		{
			cerr << "ERROR: CryptEncrypt failed. gle=" << GetLastError() << endl;
			goto done;
		}
		else
		{
			cout << "SUCCESS: CryptEncrypt succeeded. dwCount=" << dwCount << endl;



			Base64Util b64;
			retval = b64.EncodeByteArrayToString(pBuffer, dwCount);
			cout << "!!!" << retval << endl;

		}



	done:

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
			{
				cerr << "ERROR: CryptDestroyHash failed." << endl;
			}

			hHash = NULL;
		}


		if (hCryptProv)
		{
			if (!(CryptReleaseContext(hCryptProv, 0)))
			{
				cerr << "ERROR: CryptReleaseContext failed." << endl;
			}
		}

		return retval;
	}


};


class Compression
{
public:
	static vector<BYTE> CompressToVector(vector<BYTE> bytes)
	{
		vector<BYTE> retval;
		COMPRESSOR_HANDLE Compressor = NULL;



		SIZE_T dwInputBufferLength = (SIZE_T)bytes.size();
		BYTE* pvInputBuffer = new BYTE[dwInputBufferLength];

		SIZE_T dwCompressedBufferSize = 0;
		BYTE* pvCompressedBuffer = NULL;
		SIZE_T dwCompressedDataSize = 0;




		if (!CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &Compressor))
		{
			cerr << "ERROR: CreateCompressor failed. gle=" << GetLastError() << endl;
			goto done;
		}

		for (DWORD dwIndex = 0; dwIndex < dwInputBufferLength; dwIndex++)
		{
			pvInputBuffer[dwIndex] = bytes[dwIndex];
		}


		Compress(
			Compressor,
			pvInputBuffer,
			dwInputBufferLength,
			NULL,
			0,
			&dwCompressedBufferSize);


		pvCompressedBuffer = new BYTE[dwCompressedBufferSize];
		memset(pvCompressedBuffer, 0, dwCompressedBufferSize);


		if (!Compress(
			Compressor,
			pvInputBuffer,
			dwInputBufferLength,
			pvCompressedBuffer,
			dwCompressedBufferSize,
			(PSIZE_T)&dwCompressedDataSize))
		{
			cerr << "ERROR: Compress(2) failed. gle=" << GetLastError() << endl;
			goto done;
		}


		cout << "SANITY CHECK: dwCompressedBufferSize=" << dwCompressedBufferSize << " dwCompressedDataSize=" << dwCompressedDataSize << endl;

		for (DWORD dwIndex = 0; dwIndex < dwCompressedDataSize; dwIndex++)
		{
			retval.push_back(pvCompressedBuffer[dwIndex]);
		}




	done:



		if (NULL != pvInputBuffer)
		{
			delete[] pvInputBuffer;
			pvInputBuffer = NULL;
		}

		if (NULL != pvCompressedBuffer)
		{
			delete[] pvCompressedBuffer;
			pvCompressedBuffer = NULL;
		}


		if (NULL != Compressor)
		{
			CloseCompressor(Compressor);
			Compressor = NULL;
		}


		return retval;
	}

	static vector<BYTE> DecompressToVector(vector<BYTE> compressedBytes)
	{
		vector<BYTE> retval;
		DECOMPRESSOR_HANDLE Decompressor = NULL;
		tuple<BYTE*, DWORD> compressedBytesTuple = Convert::VectorToByteArray(compressedBytes);
		BYTE* CompressedBuffer = std::get<0>(compressedBytesTuple);
		SIZE_T CompressedBufferSize = std::get<1>(compressedBytesTuple);
		SIZE_T DecompressedBufferSize = 0;

		BYTE* DecompressedBuffer = NULL;
		SIZE_T DecompressedDataSize = 0;



		if (!CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &Decompressor))
		{
			cerr << "ERROR: CreateDecompressor failed." << endl;
			goto done;
		}


		Decompress(
			Decompressor,
			CompressedBuffer,
			CompressedBufferSize,
			NULL,
			0,
			&DecompressedBufferSize);


		cout << "*DecompressedBufferSize=" << DecompressedBufferSize << endl;

		DecompressedBuffer = new BYTE[DecompressedBufferSize];
		memset(DecompressedBuffer, 0, DecompressedBufferSize);


		if (Decompress(
			Decompressor,
			CompressedBuffer,
			CompressedBufferSize,
			DecompressedBuffer,
			DecompressedBufferSize,
			&DecompressedDataSize))
		{
			for (SIZE_T index = 0; index < DecompressedDataSize; index++)
			{
				retval.push_back(DecompressedBuffer[index]);
			}
		}
		else
		{
			cerr << "Decompress(2) failed. gle=" << GetLastError() << endl;
		}





	done:

		if (NULL != DecompressedBuffer)
		{
			delete[] DecompressedBuffer;
			DecompressedBuffer = NULL;
		}

		if (Decompressor != NULL)
		{
			CloseDecompressor(Decompressor);
		}


		return retval;
	}
};





class GitHubIssue
{
public:

	GitHubIssue(string n, string t, string b, string s)
	{
		number = n;
		title = t;
		body = b;
		state = s;
		label = "";
	}

	GitHubIssue(string n, string t, string b, string s, string l)
	{
		number = n;
		title = t;
		body = b;
		state = s;
		label = l;
	}


	string ToString()
	{
		string retval = "number=" + number + " state=" + state + " title=" + title + " body=" + body + " label=" + label;
		return retval;
	}

	string number;
	string title;
	string body;
	string state;
	string label;
};







class GitHubUtil
{
public:
	static string GetBlob(string blobSha)
	{
		string retval("");

		WebClient wc;
		string blobUri("/repos/USCourtsTelemetry/TestRepo/git/blobs/");
		blobUri.append(blobSha);

		string response = wc.DownloadString("api.github.com", blobUri.c_str());

		string searchFor("\\n");
		string replaceWith("");

		StringUtils::replaceAll(response, searchFor, replaceWith);

		//cout << response << endl;


		string delims("\":, ");
		vector<string> tokens = StringUtils::SplitRemoteEmptyElements(response, delims);

		for (int x = 0; x < tokens.size(); x++)
		{
			if (tokens[x].compare("content") == 0)
			{
				retval = tokens[x + 1];
				break;
			}
		}

		Base64Util b64;
		retval = b64.DecodeStringToString(retval);


		return retval;
	}


	static string CreateBlob(string blob)
	{
		string retval("");

		string createBlobTemplate("{\"content\": \"AAAA\",\"encoding\": \"utf-8\"}");
		string searchA("AAAA");

		StringUtils::replaceAll(createBlobTemplate, searchA, blob);
		WebClient webClient;
		string response = webClient.UploadString("api.github.com", "/repos/USCourtsTelemetry/TestRepo/git/blobs", "POST", (BYTE*)createBlobTemplate.c_str(), createBlobTemplate.size());
		cout << response << endl;

		string delims("\":,");
		vector<string> tokens = StringUtils::SplitRemoteEmptyElements(response, delims);

		for (int x = 0; x < tokens.size(); x++)
		{
			if (tokens[x].compare("sha") == 0)
			{
				retval = tokens[x + 1];
			}
		}

		return retval;
	}


	static void CreateIssue(string title, string body, string label)
	{
		string createIssueTemplate("{\"title\": \"AAAA\",\"body\": \"BBBB\",\"assignees\": [\"USCourtsTelemetry\"],\"labels\": [\"CCCC\"]}");
		string searchA("AAAA");
		string searchB("BBBB");
		string searchC("CCCC");

		StringUtils::replaceAll(createIssueTemplate, searchA, title);
		StringUtils::replaceAll(createIssueTemplate, searchB, body);
		StringUtils::replaceAll(createIssueTemplate, searchC, label);
		WebClient webClient;
		string response = webClient.UploadString("api.github.com", "/repos/USCourtsTelemetry/TestRepo/issues", "POST", (BYTE*)createIssueTemplate.c_str(), createIssueTemplate.size());

	}

	static void CloseIssue(string number)
	{
		char* buffer = (char*)"{\"state\": \"closed\"}";
		DWORD dwBufferLength = strlen(buffer);
		string dir("/repos/USCourtsTelemetry/TestRepo/issues/" + number);
		WebClient webClient;

		string response = webClient.UploadString("api.github.com", dir.c_str(), "PATCH", (BYTE*)buffer, dwBufferLength);
	}

	static vector<GitHubIssue> GetIssuesForMe(string hashedMe)
	{
		vector<GitHubIssue> retval;

		vector<GitHubIssue> allIsuses = GetIssues();

		for (vector<GitHubIssue>::iterator i = allIsuses.begin(); i != allIsuses.end(); i++)
		{
			if ((*i).label.compare(hashedMe) == 0)
			{
				retval.push_back(*i);
			}
		}

		return retval;
	}

	static vector<GitHubIssue> GetIssues()
	{
		vector<GitHubIssue> retval;
		WebClient wc;

		string response = wc.DownloadString("api.github.com", "/issues");

		string delims(",\":");
		vector<string> tokens = StringUtils::SplitRemoteEmptyElements(response, delims);

		string number;
		string title;
		string body;
		string state;
		string label("");

		for (DWORD dwIndex = 0; dwIndex < tokens.size(); dwIndex++)
		{

			//			cout << tokens[dwIndex] << endl;


			if (tokens[dwIndex].compare("labels") == 0)
			{
				label = tokens[dwIndex + 10];
			}

			if (tokens[dwIndex].compare("number") == 0)
			{
				number = tokens[dwIndex + 1];
			}

			if (tokens[dwIndex].compare("title") == 0)
			{
				title = tokens[dwIndex + 1];
			}

			if (tokens[dwIndex].compare("state") == 0)
			{
				state = tokens[dwIndex + 1];
			}

			if (tokens[dwIndex].compare("body") == 0)
			{
				body = tokens[dwIndex + 1];
				GitHubIssue gitHubIssue(number, title, body, state, label);
				retval.push_back(gitHubIssue);

			}

		}



		return retval;
	}


};







//
//
//











#endif