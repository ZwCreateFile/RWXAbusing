#include "driver.h"
#include  <mutex>

typedef bool(__fastcall* NtQueryAuxiliaryCounterFrequencyfn)(PVOID Parm);
NtQueryAuxiliaryCounterFrequencyfn NtQueryAuxiliaryCounterFrequency = nullptr;

constexpr auto packet_magic = 0x65421546;

typedef struct _GET_MODULE_HANDLE
{
	WCHAR MoudleName[256];
	HANDLE Target;
}GET_MODULE_HANDLE, * PGET_MODULE_HANDLE;

typedef struct _READ_WRITE
{
	PVOID Address;
	PVOID Buffer;
	size_t Size;
	HANDLE Target;
	BOOL write;
}READ_WRITE, * PREAD_WRITE;

typedef struct _ALLOC_MEM
{
	HANDLE Target;
	PVOID Address;
	size_t Size;
	unsigned int AllocationType;
	unsigned int AllocationProtect;
}ALLOC_MEM, * PALLOC_MEM;

typedef struct _FREE_MEM
{
	HANDLE Target;
	PVOID Address;
}FREE_MEM, * PFREE_MEM;

typedef struct _PROTECT_MEM
{
	HANDLE Target;
	PVOID Address;
	SIZE_T Size;
	DWORD NewProtection;
	DWORD OldProtection;
}PROTECT_MEM, * PPROTECT_MEM;

enum class type
{
	_invalid,
	_memoryop = 70,
	_get_mod_address = 87,
	_alloc_mem = 98,
	_free_mem = 32,
	_protect_mem = 15,
	_isloaded = 65,
	_unload = 56,
};


struct HEADER
{
	uint32_t   magic;
	type type;
};

struct Packet
{
	HEADER header;
	union
	{
		PVOID _memory;
		uint64_t result;
	} data;
};

#define DllExport extern "C" __declspec( dllexport )

DllExport Packet data;

std::mutex shareptr;
Packet data;

namespace Driver
{
	BOOL Setup()
	{
		NtQueryAuxiliaryCounterFrequency = reinterpret_cast<NtQueryAuxiliaryCounterFrequencyfn>(GetProcAddress(LoadLibraryA(("ntdll.dll")), ("NtQueryAuxiliaryCounterFrequency")));

		return CheckLoaded();
	}

	bool CheckLoaded()
	{
		shareptr.lock();
		memset(&data, 0x0, sizeof(Packet));

		data.header.magic = packet_magic;
		data.header.type = type::_isloaded;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);
		bool resutl = (data.data.result > 0);
		shareptr.unlock();

		void* base = *reinterpret_cast<void**>(__readgsqword(0x60) + 0x10);

		PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		PIMAGE_NT_HEADERS64 pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>((reinterpret_cast<LPBYTE>(base) + pDosHeader->e_lfanew));

		DWORD old;
		VirtualProtect(base, pNtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &old);
		memset(base, 0x0, pNtHeaders->OptionalHeader.SizeOfHeaders);
		VirtualProtect(base, pNtHeaders->OptionalHeader.SizeOfHeaders, old, &old);
		return resutl;
	}

	void Unload()
	{
		shareptr.lock();
		memset(&data, 0x0, sizeof(Packet));

		data.header.magic = packet_magic;
		data.header.type = type::_unload;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);
		shareptr.unlock();
	}

	bool Process::NtKeWrite(PVOID dest, PVOID src, DWORD size) {
		static PREAD_WRITE req;
		if (!req)
			req = new READ_WRITE();

		if (!dest || !src)
			return false;

		shareptr.lock();
		memset(req, 0x0, sizeof(READ_WRITE));
		memset(&data, 0x0, sizeof(Packet));

		req->Target = (HANDLE)this->ProcessId;
		req->Address = dest;
		req->Buffer = src;
		req->Size = size;
		req->write = true;

		data.header.magic = packet_magic;
		data.header.type = type::_memoryop;
		data.data._memory = (void*)req;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);

		data.header.type = type::_invalid;

		bool resutl = (data.data.result == 0x00000000L);

		shareptr.unlock();
		return true;
	}

	bool Process::NtKeRead(PVOID dest, PVOID src, DWORD size)
	{
		static PREAD_WRITE req;
		if (!req)
			req = new READ_WRITE();

		if (!dest || !src)
			return false;

		shareptr.lock();
		memset(req, 0x0, sizeof(READ_WRITE));
		memset(&data, 0x0, sizeof(Packet));

		req->Target = (HANDLE)this->ProcessId;
		req->Address = src;
		req->Buffer = dest;
		req->Size = size;
		req->write = false;

		data.header.magic = packet_magic;
		data.header.type = type::_memoryop;
		data.data._memory = (void*)req;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);

		data.header.type = type::_invalid;

		bool resutl = (data.data.result == 0x00000000L);
		shareptr.unlock();
		return resutl;
	}

	bool Process::NtiModule(LPCWSTR moduleName, PBYTE* base)
	{
		static PGET_MODULE_HANDLE req;
		if (!req)
			req = new GET_MODULE_HANDLE();

		shareptr.lock();
		memset(req, 0x0, sizeof(GET_MODULE_HANDLE));
		memset(&data, 0x0, sizeof(Packet));

		req->Target = (HANDLE)this->ProcessId;

		wcscpy_s(req->MoudleName, sizeof(req->MoudleName) / sizeof(req->MoudleName[0]), moduleName);

		data.header.magic = packet_magic;
		data.header.type = type::_get_mod_address;
		data.data._memory = (void*)req;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);

		*base = (PBYTE)data.data.result;

		data.header.type = type::_invalid;
		bool resutl = (data.data.result > 0);
		shareptr.unlock();
		return resutl;
	}

	bool Process::Alloc(SIZE_T size, DWORD Protect, PVOID* AllocatedAt)
	{
		static PALLOC_MEM req;
		if (!req)
			req = new ALLOC_MEM();

		shareptr.lock();
		memset(req, 0x0, sizeof(ALLOC_MEM));
		memset(&data, 0x0, sizeof(Packet));

		req->Target = (HANDLE)this->ProcessId;
		req->Address = nullptr;
		req->AllocationProtect = Protect;
		req->AllocationType = MEM_COMMIT | MEM_RESERVE;
		req->Size = size;

		data.header.magic = packet_magic;
		data.header.type = type::_alloc_mem;
		data.data._memory = (void*)req;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);

		data.header.type = type::_invalid;

		bool resutl = (data.data.result == 0x00000000L);
		shareptr.unlock();

		*AllocatedAt = req->Address;

		return resutl;
	}

	bool Process::Free(PVOID addr)
	{
		static PFREE_MEM req;
		if (!req)
			req = new FREE_MEM();

		shareptr.lock();
		memset(req, 0x0, sizeof(FREE_MEM));
		memset(&data, 0x0, sizeof(Packet));

		req->Target = (HANDLE)this->ProcessId;
		req->Address = addr;

		data.header.magic = packet_magic;
		data.header.type = type::_free_mem;
		data.data._memory = (void*)req;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);

		data.header.type = type::_invalid;

		bool resutl = (data.data.result == 0x00000000L);
		shareptr.unlock();

		return resutl;
	}

	bool Process::Protect(PVOID addr, DWORD Size, DWORD NewProtect, DWORD* OldProtect)
	{
		static PPROTECT_MEM req;
		if (!req)
			req = new PROTECT_MEM();

		shareptr.lock();
		memset(req, 0x0, sizeof(PROTECT_MEM));
		memset(&data, 0x0, sizeof(Packet));

		req->Target = (HANDLE)this->ProcessId;
		req->Address = addr;
		req->NewProtection = NewProtect;
		req->Size = Size;

		data.header.magic = packet_magic;
		data.header.type = type::_protect_mem;
		data.data._memory = (void*)req;

		PVOID dummy;
		NtQueryAuxiliaryCounterFrequency(&dummy);

		data.header.type = type::_invalid;

		bool resutl = (data.data.result == 0x00000000L);
		shareptr.unlock();

		*OldProtect = req->OldProtection;

		return true;
	}


}
