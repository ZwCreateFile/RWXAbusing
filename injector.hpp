#pragma once
BYTE EntryPointShellcode[] = { 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x10, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x50, 0x08, 0x48, 0x83, 0xEC, 0x28, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0x48, 0x31, 0xC0, 0xC6, 0x05, 0xAE, 0xFF, 0xFF, 0xFF, 0x01, 0xC3 };
#define WidenString(ansii) (std::wstring(ansii, &ansii[strlen(ansii)]).c_str())

PIMAGE_NT_HEADERS GetDllNtHeaders(ULONG_PTR DllBase)
{
	if (!DllBase) return NULL;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(DllBase + ((PIMAGE_DOS_HEADER)DllBase)->e_lfanew);

	if (NtHeaders->Signature == IMAGE_NT_SIGNATURE)
	{
		return NtHeaders;
	}

	return NULL;
}

PIMAGE_SECTION_HEADER TranslateRawSection(PIMAGE_NT_HEADERS NTHeaders, DWORD RVA)
{
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NTHeaders);
	for (auto i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++, Section++)
	{
		if (RVA >= Section->VirtualAddress && RVA < Section->VirtualAddress + Section->Misc.VirtualSize)
		{
			return Section;
		}
	}

	return NULL;
}
PVOID TranslateRaw(PBYTE DllBase, PIMAGE_NT_HEADERS NTHeaders, DWORD RVA)
{
	auto Section = TranslateRawSection(NTHeaders, RVA);
	if (!Section) return NULL;

	return DllBase + Section->PointerToRawData + (RVA - Section->VirtualAddress);
}

bool ResolveImports(Driver::Process Process, PBYTE DllBase, PIMAGE_NT_HEADERS NTHeaders)
{
	printf("\n[+] Resolving imports!\n");

	ULONG ImportsVirtualAddress = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!ImportsVirtualAddress) return true;

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)TranslateRaw(DllBase, NTHeaders, ImportsVirtualAddress);
	if (!ImportDescriptor) return true;

	for (; ImportDescriptor->FirstThunk; ImportDescriptor++)
	{
		auto ModuleName = (PCHAR)TranslateRaw(PBYTE(DllBase), NTHeaders, ImportDescriptor->Name);
		if (!ModuleName) break;

		auto Module = LoadLibraryA(ModuleName);
		if (!Module)
		{
			printf("[-] Failed to load imported module: %s!\n", ModuleName);
			return false;
		}

		PBYTE RemoteModuleAddress = (PBYTE)Process.mod(WidenString(ModuleName));
		if (!RemoteModuleAddress)
		{
			printf("[-] Target process does not have %s loaded!\n", ModuleName);
			return false;
		}

		for (auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(TranslateRaw(DllBase, NTHeaders, ImportDescriptor->FirstThunk)); thunk->u1.AddressOfData; thunk++)
		{
			auto importByName = (PIMAGE_IMPORT_BY_NAME)(TranslateRaw(DllBase, NTHeaders, (DWORD)thunk->u1.AddressOfData));
			thunk->u1.Function = (ULONG_PTR)(RemoteModuleAddress + ((PBYTE)(GetProcAddress(Module, importByName->Name)) - (PBYTE)Module));
		}
		printf("[+] %s resolved!\n", ModuleName);
	}
	printf("[+] Resolved imports!\n");

	return true;
}
void ResolveRelocations(PBYTE DllBase, PIMAGE_NT_HEADERS NTHeaders, PBYTE Mapped)
{
	printf("\n[+] Resolving relocations!\n");

	auto& RelocateDirectoryBase = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!RelocateDirectoryBase.VirtualAddress)
	{
		return;
	}

	auto BaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(TranslateRaw(DllBase, NTHeaders, RelocateDirectoryBase.VirtualAddress));
	if (!BaseRelocation) return;

	for (auto CurrentSize = 0UL; CurrentSize < RelocateDirectoryBase.Size; )
	{
		auto RelocationsCount = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		auto RelocationData = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(BaseRelocation) + sizeof(IMAGE_BASE_RELOCATION));
		auto RelocationBase = reinterpret_cast<PBYTE>(TranslateRaw(DllBase, NTHeaders, BaseRelocation->VirtualAddress));

		for (auto i = 0UL; i < RelocationsCount; i++, ++RelocationData)
		{
			auto data = *RelocationData;
			auto type = data >> 12;
			auto offset = data & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
			{
				*(PBYTE*)(RelocationBase + offset) += (Mapped - (PBYTE)(NTHeaders->OptionalHeader.ImageBase));
			}
		}

		CurrentSize += BaseRelocation->SizeOfBlock;
		BaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(RelocationData);
	}

	printf("[+] Resolved relocations!\n");
}

ULONG_PTR HeaderVA;
ULONG_PTR HeaderSIZE;
bool MapHeaders(Driver::Process Process, PBYTE DllBase, PIMAGE_NT_HEADERS NTHeaders, PBYTE Mapped)
{
	HeaderSIZE = sizeof(NTHeaders->Signature) + sizeof(NTHeaders->FileHeader) + NTHeaders->FileHeader.SizeOfOptionalHeader;
	HeaderVA = ULONG_PTR(Mapped);
	return Process.NtKeWrite(Mapped, DllBase, HeaderSIZE);
}
bool FreeHeaders(Driver::Process Process, PIMAGE_NT_HEADERS NTHeaders, PBYTE Mapped)
{
	return Process.Free(Mapped);
}
bool MapSections(Driver::Process Process, PBYTE DllBase, PIMAGE_NT_HEADERS NTHeaders, PBYTE Mapped)
{
	auto Section = IMAGE_FIRST_SECTION(NTHeaders);
	for (auto i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++, Section++)
	{
		ULONG SectionSize = min(Section->SizeOfRawData, Section->Misc.VirtualSize);
		if (!SectionSize) continue;

		auto MappedSection = Mapped + Section->VirtualAddress;
		if (!Process.NtKeWrite(MappedSection, DllBase + Section->PointerToRawData, SectionSize))
		{
			printf("[-] Failed to map section [%s] -> [0x%llx] (Size: 0x%lx)!\n", Section->Name, ULONG_PTR(MappedSection), SectionSize);
			return false;
		}
		printf("[+] Successfully mapped section [%s] -> [0x%llx] (Size: 0x%lx)!\n", Section->Name, ULONG_PTR(MappedSection), SectionSize);
	}

	return true;
}


PBYTE MapToAddress(Driver::Process Process, PBYTE DllBase, PIMAGE_NT_HEADERS NTHeaders, PBYTE Mapped, SIZE_T AllowedSize)
{
	printf("\n[+] Mapping headers!\n");
	if (!MapHeaders(Process, DllBase, NTHeaders, Mapped))
	{
		printf("[-] Failed to map headers!\n");
		return nullptr;
	}
	printf("[+] Successfully mapped headers!\n");

	printf("\n[+] Mapping sections!\n");
	if (!MapSections(Process, DllBase, NTHeaders, Mapped))
	{
		printf("[-] Failed to map sections!\n");
		return nullptr;
	}
	printf("[+] Successfully mapped sections!\n");

	return Mapped + NTHeaders->OptionalHeader.AddressOfEntryPoint;
}
bool HijackViaHook(Driver::Process Process, PBYTE EntryPoint, PBYTE ShellcodeEntry, const wchar_t* ModuleName, const char* FunctionName)
{
	printf("\n[+] Calling entry point: 0x%llx!\n", ULONG_PTR(EntryPoint));
	PBYTE RemoteModule = (PBYTE)Process.mod(ModuleName);
	if (!RemoteModule)
	{
		printf("[-] Target process does not have %ws loaded!\n", ModuleName);
		return false;
	}

	auto Module = LoadLibraryW(ModuleName);
	if (!Module)
	{
		printf("[-] Failed to load module: %ws!\n", ModuleName);
		return false;
	}

	auto Function = (PBYTE)GetProcAddress(Module, FunctionName);
	if (!Function)
	{
		printf("[-] Failed to find export: %s in module: %ws!\n", FunctionName, ModuleName);
		return false;
	}

	auto RemoteFunction = RemoteModule + (Function - reinterpret_cast<PBYTE>(Module));
	*reinterpret_cast<PVOID*>(&EntryPointShellcode[3]) = RemoteFunction;
	Process.NtKeRead(&EntryPointShellcode[13], RemoteFunction, sizeof(ULONG64));
	Process.NtKeRead(&EntryPointShellcode[26], RemoteFunction + sizeof(ULONG64), sizeof(ULONG64));
	*reinterpret_cast<PVOID*>(&EntryPointShellcode[60]) = EntryPoint;

	auto MappedShellcode = ShellcodeEntry;
	if (Process.NtKeWrite(MappedShellcode, EntryPointShellcode, sizeof(EntryPointShellcode)))
	{
		printf("[+] Shellcode written at: 0x%llx!\n", ULONG_PTR(MappedShellcode));
	}
	else
	{
		printf("[-] Failed to write shellcode at: 0x%llx!\n", ULONG_PTR(MappedShellcode));
		return false;
	}
	BYTE Jump[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
	*reinterpret_cast<PVOID*>(&Jump[6]) = MappedShellcode + 1;


	ULONG Protect = PAGE_EXECUTE_READWRITE;
	DWORD old1;
	if (!Process.Protect(RemoteFunction, 2 * sizeof(ULONG64), Protect, &old1))
	{
		printf("[-] Failed to protect 0x%llx!\n", ULONG_PTR(RemoteFunction));
		return false;
	}
	if (!Process.NtKeWrite(RemoteFunction, Jump, sizeof(Jump)))
	{
		printf("[-] Failed to write jump!\n");
		return false;
	}

	printf("[+] Waiting for written shellcode to execute.\n");
	for (auto FunctionBytes = 0ULL;; Sleep(1))
	{
		if (!Process.NtKeRead(&FunctionBytes, RemoteFunction + 6, sizeof(FunctionBytes)))
		{
			printf("[-] Failed to read function bytes at 0x%llx!\n", ULONG_PTR(RemoteFunction + 6));
			return false;
		}
		if (FunctionBytes != *reinterpret_cast<PULONG64>(&Jump[6])) break;
	}
	printf("[+] Shellcode hook called!\n");
	DWORD old;
	if (!Process.Protect(RemoteFunction, sizeof(Jump), Protect, &old))
	{
		printf("[-] Failed to protect 0x%llx!\n", ULONG_PTR(RemoteFunction + 6));
		return false;
	}

	for (BYTE Status = 0;; Sleep(1))
	{
		if (!Process.NtKeRead(&Status, MappedShellcode, sizeof(Status)))
		{
			printf("[-] Failed to read shellcode status at 0x%llx!\n", ULONG_PTR(MappedShellcode));
			return false;
		}
		if (Status) break;
	}

	Process.Free(MappedShellcode);
	printf("[+] Released shellcode at: 0x%llx!\n", ULONG_PTR(MappedShellcode));

	Process.Free((PVOID)HeaderVA);
	printf("[+] Released headers at: 0x%llx!\n", HeaderVA);

	return true;
}
bool InjectToAddress(Driver::Process Process, PBYTE DllBase, ULONG DllSize, PBYTE Mapped, SIZE_T AllowedSize)
{
	ULONG_PTR RwxEnd = ULONG_PTR(Mapped) + AllowedSize;
	if ((DllSize + (sizeof(EntryPointShellcode) + 5)) > AllowedSize)
	{
		PrintDebugInfo("[-] RWX section is too small to fit the current DLL!\n");
		return false;
	}

	PIMAGE_NT_HEADERS NTHeaders = GetDllNtHeaders((ULONG_PTR)DllBase);
	if (!ResolveImports(Process, DllBase, NTHeaders))
	{
		printf("[-] Failed to resolve imports!\n");
		return false;
	}

	ResolveRelocations(DllBase, NTHeaders, Mapped);

	PBYTE ShellcodeEntry = (PBYTE)(RwxEnd - (sizeof(EntryPointShellcode) + 5));
	PBYTE EntryPoint = MapToAddress(Process, DllBase, NTHeaders, Mapped, AllowedSize);

	if (HijackViaHook(Process, EntryPoint, ShellcodeEntry, L"kernel32.dll", "Sleep"))
	{
		printf("[+] DLL executed!\n\n");
		return true;
	}
	else
	{
		printf("[-] Failed to execute DLL!\n\n");
		return false;
	}
}