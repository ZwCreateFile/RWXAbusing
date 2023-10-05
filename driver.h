#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <fstream>
#include <vector>

struct CharStruct {
	char string[256];
};

#define DEBUG_PRINTS

#ifdef DEBUG_PRINTS
#define PrintDebugInfo(format, ...) printf(format, __VA_ARGS__)
#else // !DEBUG_PRINTS
#define PrintDebugInfo(format, ...)
#endif // DEBUG_PRINTS

namespace Driver
{

	BOOL Setup();
	bool CheckLoaded();
	void Unload();

	class Process {
	public:
		bool NtKeWrite(PVOID dest, PVOID src, DWORD size);
		bool NtKeRead(PVOID dest, PVOID src, DWORD size);
		bool NtiModule(LPCWSTR moduleName, PBYTE* base);
		bool Alloc(SIZE_T size, DWORD Protect, PVOID* AllocatedAt);
		bool Free(PVOID addr);
		bool Protect(PVOID addr, DWORD Size, DWORD NewProtect, DWORD* OldProtect);
		DWORD ProcessId = 0;
		Process(DWORD processId) : ProcessId{ processId } {}
		ULONG64 mod(LPCWSTR moduleName) {
			if (!moduleName)
				return 0;

			BYTE* modAddr = 0;
			this->NtiModule(moduleName, &modAddr);

			return (ULONG64)modAddr;
		}

		template <class C>
		C read(UINT_PTR addr) {
			C temp{};

			if (!PVOID(addr))
				return temp;
			//ADDR RECIVES DATA
			this->NtKeRead(&temp, PVOID(addr), sizeof(C));
			return temp;
		}

		void read(DWORD64 addr, PVOID buff, DWORD size) {
			if (!(PVOID)addr)
				return;

			this->NtKeRead(buff, (PVOID)addr, size);
			return;
		}

		void readNormal(UINT_PTR ReadAddress, void* buffer, uintptr_t size) {
			this->NtKeRead(&buffer, PVOID(ReadAddress), size);
		}

		template<typename S>
		bool write(UINT_PTR addr, const S dest) {
			if (!PVOID(addr))
				return false;
			return this->NtKeWrite(PVOID(addr), (PVOID)&dest, sizeof(S));
		};

		std::string read_string(UINT_PTR String_address, SIZE_T size)
		{
			std::unique_ptr<char[]> buffer(new char[size]);
			this->NtKeRead(PVOID(String_address), buffer.get(), size);
			return std::string(buffer.get());
		}

		std::wstring read_wstring(UINT_PTR String_address, SIZE_T size)
		{
			const auto buffer = std::make_unique<wchar_t[]>(size);
			this->NtKeRead(PVOID(String_address), buffer.get(), size * 2);
			return std::wstring(buffer.get());
		}

		auto ReadUnicode(uint64_t address)
		{
			return read_wstring(address, 32);
		}

		template <class C>
		C read_chain(uintptr_t addr, std::vector<uint64_t> bytes) {
			uint64_t buffer;

			if (buffer = read<uint64_t>(addr + bytes[0])) {
				for (int i = 1; i < bytes.size() - 1; i++) {
					if (buffer = read<uint64_t>(buffer + bytes[i]))
						continue;
					return 0;
				}

				return read<C>(buffer + bytes.back());
			}
			return 0;
		}
	};
}