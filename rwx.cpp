#include <iostream>
#include <Windows.h>
#include "driver.h"
#include <tchar.h>
#include "injector.hpp"
#define PROC_INJECTIONW L"EscapeFromTarkov.exe"
#define PROC_INJECTION "EscapeFromTarkov.exe"


ULONG_PTR GetDllSectionFromName(ULONG_PTR DllBase, const char* SectionName, ULONG_PTR& OutSize)
{
	if (!DllBase) return NULL;
	PIMAGE_NT_HEADERS NtHeaders = GetDllNtHeaders(DllBase);
	if (NtHeaders)
	{
		IMAGE_FILE_HEADER FileHeader = NtHeaders->FileHeader;
		IMAGE_OPTIONAL_HEADER OptionalHeader = NtHeaders->OptionalHeader;

		PIMAGE_SECTION_HEADER SectionHeader = nullptr;

		int i = 0;
		for (SectionHeader = IMAGE_FIRST_SECTION(NtHeaders), i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, SectionHeader++)
		{
			const char* CurrentSectionName = ((const char*)SectionHeader->Name);
			if (strcmp(CurrentSectionName, SectionName) == NULL)
			{
				OutSize = ULONG_PTR(SectionHeader->SizeOfRawData);
				return ULONG_PTR(SectionHeader->VirtualAddress);
			}
		}
	}

	return NULL;
}


bool IsProcessRunning(const std::wstring& ProcessName)
{
	bool exists = false;
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32FirstW(snapshot, &entry))
	{
		while (Process32NextW(snapshot, &entry))
		{
			if (!_wcsicmp(entry.szExeFile, ProcessName.c_str()))
				exists = true;
		}
	}
	CloseHandle(snapshot);
	return exists;
}
int GetProcessThreadNumByID(DWORD dwPID)
{
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);
	BOOL bRet = ::Process32First(hProcessSnap, &pe32);;
	while (bRet)
	{
		if (pe32.th32ProcessID == dwPID)
		{
			::CloseHandle(hProcessSnap);
			return pe32.cntThreads;
		}
		bRet = ::Process32Next(hProcessSnap, &pe32);
	}
	return 0;
}

DWORD FindProcessId()
{
	DWORD dwRet = 0;
	DWORD dwThreadCountMax = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe32);
	do
	{
		if (_tcsicmp(pe32.szExeFile, _T(PROC_INJECTION)) == 0)
		{
			DWORD dwTmpThreadCount = GetProcessThreadNumByID(pe32.th32ProcessID);

			if (dwTmpThreadCount > dwThreadCountMax)
			{
				dwThreadCountMax = dwTmpThreadCount;
				dwRet = pe32.th32ProcessID;
			}
		}
	} while (Process32Next(hSnapshot, &pe32));
	CloseHandle(hSnapshot);
	return dwRet;
}
std::string ExePath() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return  std::string(buffer).substr(0, pos);
}
const char* GetFileNameFromPath(const char* FilePath)
{
	USHORT Length = (USHORT)strlen(FilePath);
	LONG LastSlashPos = -1;
	for (USHORT i = 0; i < Length; i++)
	{
		if (FilePath[i] == '\\') LastSlashPos = i;
	}
	return FilePath + LastSlashPos + 1;
}
DWORD PID_GAME;
ULONG GetProcessMainThreadID()
{
	THREADENTRY32 Entry;
	Entry.dwSize = sizeof(THREADENTRY32);
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (Thread32First(Snapshot, &Entry))
	{
		while (Thread32Next(Snapshot, &Entry))
		{
			if (Entry.th32OwnerProcessID == PID_GAME)
			{
				CloseHandle(Snapshot);
				return Entry.th32ThreadID;
			}
		}
	}
	CloseHandle(Snapshot);
	return NULL;
}
HHOOK LoadVulnerableDriver(
	const wchar_t* VulnerableDllName,
	const wchar_t* VulnerableDllPath,
	const char* VunerableDllSectionName,
	const char* ExportName,
	ULONG_PTR& outVulnerableDllSectionAddress,
	ULONG_PTR& outVulnerableDllSectionSize)
{
	HMODULE VulnerableDll = LoadLibraryExW(VulnerableDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!VulnerableDll)
	{
		PrintDebugInfo("[-] %ws was not found!\n", VulnerableDllPath);
		return nullptr;
	}
	PrintDebugInfo("[+] %ws address: 0x%llx!\n", VulnerableDllName, (ULONG_PTR)VulnerableDll);
	ULONG_PTR VulnerableDllSectionSize = NULL;
	ULONG_PTR VulnerableDllVirtualAddress = GetDllSectionFromName((ULONG_PTR)VulnerableDll, VunerableDllSectionName, VulnerableDllSectionSize);
	if (!VulnerableDllVirtualAddress || !VulnerableDllSectionSize)
	{
		PrintDebugInfo("[-] Failed to find section %s in %ws!\n", VunerableDllSectionName, VulnerableDllName);
		FreeLibrary(VulnerableDll);
		return nullptr;
	}
	PrintDebugInfo("[+] %ws!%s address: 0x%llx, size: 0x%llx!\n", VulnerableDllName, VunerableDllSectionName, VulnerableDllVirtualAddress, VulnerableDllSectionSize);
	HOOKPROC ExportAddress = (HOOKPROC)GetProcAddress(VulnerableDll, ExportName);
	if (!ExportAddress)
	{
		PrintDebugInfo("[-] Export: \"%s\" was not found in %ws!\n", ExportName, VulnerableDllName);
		FreeLibrary(VulnerableDll);
		return nullptr;
	}
	PrintDebugInfo("[+] \"%s\" address: 0x%llx!\n", ExportName, (ULONG_PTR)ExportAddress);

	HHOOK Hook = SetWindowsHookExW(WH_GETMESSAGE, ExportAddress, VulnerableDll, GetProcessMainThreadID());
	if (!Hook)
	{
		printf("[-] SetWindowsHook failed!");
		FreeLibrary(VulnerableDll);
		return nullptr;
	}
	PostThreadMessageW(GetProcessMainThreadID(), WM_NULL, NULL, NULL);
	PrintDebugInfo("[+] SetWindowsHook result: 0x%llx (Hook has been set and triggered)!\n", (ULONG_PTR)Hook);
	//FreeLibrary(VulnerableDll);
	outVulnerableDllSectionAddress = VulnerableDllVirtualAddress;
	outVulnerableDllSectionSize = VulnerableDllSectionSize;
	return Hook;
}

bool InjectorInitialise(Driver::Process pr, const wchar_t* ProcessName, PBYTE DllBase, ULONG DllSize)
{
	printf("[+] %ws main module base address: 0x%llx\n", PROC_INJECTION, pr.mod(PROC_INJECTIONW));

	const wchar_t* VulnerableDllName = L"DxtoryMM64.dll";
	const wchar_t* VulnerableDllPath = L"C:\\Windows\\DxtoryMM64.dll";
	const char* VunerableDllSectionName = ".EXEMEM";
	const char* VulnerableExportName = "FreeExecuteMemory";


	ULONG_PTR VulnerableSectionVA = NULL; SIZE_T VulnerableSectionSize = NULL;
	HHOOK RemoteHook = LoadVulnerableDriver(VulnerableDllName, VulnerableDllPath, VunerableDllSectionName, VulnerableExportName, VulnerableSectionVA, VulnerableSectionSize);
	if (RemoteHook)
	{
		auto RemoteVulnerableDllBase = pr.mod(VulnerableDllName);
		while (!RemoteVulnerableDllBase)
		{
			static int TimeoutLoops = 0;
			if (TimeoutLoops > 15) break;
			if (!IsProcessRunning(PROC_INJECTIONW)) break;
			RemoteVulnerableDllBase = pr.mod(VulnerableDllName);
			Sleep(2500);
			TimeoutLoops++;
		}
		if (!RemoteVulnerableDllBase)
		{
			printf("[-] Timed out waiting for remote vulnerable DLL base!\n");
			return false;
		}
		PrintDebugInfo("[+] %ws remote base address: 0x%llx!\n", VulnerableDllName, RemoteVulnerableDllBase);
		PBYTE RWXBase = PBYTE(RemoteVulnerableDllBase + VulnerableSectionVA);
		PrintDebugInfo("[+] %ws remote RWX section address: 0x%llx!\n", VulnerableDllName, ULONG_PTR(RWXBase));
		if (!InjectToAddress(pr, DllBase, DllSize, RWXBase, VulnerableSectionSize))
		{
			printf("[-] Injection was not successful.\n");
		}

		printf("[+] Press any key to unload injection from %ws.\n", ProcessName);
		system("pause >nul 2>&1");
	}
	else
	{
		printf("[-] Failed to load vulnerable DLL into %ws!\n", PROC_INJECTION);
		return false;
	}
}

int main()
{
	if (!Driver::Setup())
	{
		printf("!!\n");
	}
	PID_GAME = FindProcessId();

	Driver::Process process(PID_GAME);

	if (!Driver::CheckLoaded())
	{
		printf("[-] Driver is not loaded!\n");
	}
	else
	{
		printf("[+] Driver is loaded!\n\n");
		std::string DllPath = ExePath() + "\\cheat.dll";
		const wchar_t* GameName = PROC_INJECTIONW;
		printf("[+] Injecting \"%s\" into \"%ws\"!\n", GetFileNameFromPath(DllPath.c_str()), GameName);
		std::ifstream FileDragged(DllPath, std::ios::ate | std::ios::binary);
		auto FileSize = FileDragged.tellg();
		auto Buffer = new BYTE[FileSize];
		FileDragged.seekg(0, std::ios::beg);
		FileDragged.read(reinterpret_cast<PCHAR>(Buffer), FileSize);
		FileDragged.close();

		InjectorInitialise(process, GameName, Buffer, FileSize);

	}
	system("pause");
}
