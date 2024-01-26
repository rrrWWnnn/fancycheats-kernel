#include <ntifs.h>
#include <intrin.h>
#include "Patch.h"

extern "C" NTKERNELAPI NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING ObjectName, IN ULONG Attributes, IN PACCESS_STATE PassedAccessState, IN ACCESS_MASK DesiredAccess, IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, IN OUT PVOID ParseContext, OUT PVOID * Object);
extern "C" POBJECT_TYPE* IoDriverObjectType;

static PVOID lastPatch = nullptr;
static char lastData[32];

PVOID Patch::GetShellCode(uintptr_t address)
{
	const char* shellcode = "\x48\x31\xc0\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"; // 16

	PVOID allocated = ExAllocatePool(NonPagedPool, 16);
	if (!allocated)
		return 0;

	memcpy(allocated, shellcode, 16);

	*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(allocated) + 5) = address;

	return allocated;
}

void Patch::JmpTo(PVOID function, PVOID target)
{
	PVOID shellcode = GetShellCode(reinterpret_cast<uintptr_t>(target));

	_disable();

    auto cr0 = __readcr0();
    auto oldCr0 = cr0;
    cr0 &= ~(1UL << 16);
    __writecr0(cr0);

	if (!lastPatch)
	{
		lastPatch = function;
		memcpy(lastData, function, 16);
	}	
	
	memcpy(function, shellcode, 16);

	__writecr0(oldCr0);

	_enable();
	
	ExFreePool(shellcode);
}

void Patch::RestoreJmpTo()
{
	_disable();

	auto cr0 = __readcr0();
	auto oldCr0 = cr0;
	cr0 &= ~(1UL << 16);
	__writecr0(cr0);
	
	memcpy(lastPatch, lastData, 16);
	
	__writecr0(oldCr0);

	_enable();
}

PVOID Patch::DrvObj(UNICODE_STRING name, PVOID target)
{
	UNREFERENCED_PARAMETER(target);

	PDRIVER_OBJECT object = nullptr;
	NTSTATUS status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, reinterpret_cast<PVOID*>(&object));
	if (!NT_SUCCESS(status) || !object)
	{
		return nullptr;
	}

	uintptr_t entry = reinterpret_cast<uintptr_t>(*object->DriverUnload);
	if (!entry)
	{
		return nullptr;
	}

	JmpTo(reinterpret_cast<PVOID>(entry), target);

	return reinterpret_cast<PVOID>(entry);
}
