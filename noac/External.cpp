#include <ntifs.h>
#include "Shared.h"
#include "Xor.h"

#pragma warning(push, 0) // bruh

#define HANDLE_VALUE_SIZE 4

#define SIZE_OF_HANDLE_TABLE	PAGE_SIZE

#define TABLE_COUNT_LOW (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY_WIN10))
#define TABLE_COUNT_HIGH (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY_WIN10))

// FIXME: this changes like shit in win updates
// also check the structs with WinDbg
#define HANDLE_TABLE_ADDRESS_WIN10	0x418 //0x418
#define HANDLE_TABLE_ADDRESS_WIN10_2004	0x570

extern "C" NTKERNELAPI PVOID NTAPI
ObGetObjectType(
	IN PVOID pObject
);

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2

static HANDLE lastProcess;
static PEPROCESS lastPeprocess;

typedef struct _MM_COPY_ADDRESS {
	union {
		PVOID            VirtualAddress;
		PHYSICAL_ADDRESS PhysicalAddress;
	};
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

extern "C" NTSTATUS NTAPI MmCopyMemory(
	PVOID           TargetAddress,
	MM_COPY_ADDRESS SourceAddress,
	SIZE_T          NumberOfBytes,
	ULONG           Flags,
	PSIZE_T         NumberOfBytesTransferred
);

NTSTATUS CopyVirtual(PVOID target, PVOID source, SIZE_T size)
{
	NTSTATUS status;
	SIZE_T trasfered = 0;
	MM_COPY_ADDRESS address = { 0 };
	address.VirtualAddress = source;

	if (reinterpret_cast<uintptr_t>(source) < 100000 || reinterpret_cast<uintptr_t>(target) < 100000)
		return STATUS_UNSUCCESSFUL;
	
	PEPROCESS EProcess = nullptr;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(lastProcess, &EProcess)))
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (lastPeprocess != EProcess)
	{
		ObDereferenceObject(EProcess);
		return STATUS_UNSUCCESSFUL;
	}

	ObDereferenceObject(EProcess);	
	
	if (size < 100000)
	{
		status = MmCopyMemory(target, address, size, MM_COPY_MEMORY_VIRTUAL, &trasfered);
	} else
	{
		status = STATUS_UNSUCCESSFUL;
	}

	return status;
}

template<typename T>
T ReadVirtualKernel(PVOID address, bool* success = nullptr)
{
	T val = T();

	SIZE_T returned = 0;
	NTSTATUS status = CopyVirtual(&val, address, sizeof(T));

	if (success)
	{
		if (NT_SUCCESS(status))
		{
			*success = true;
		}
		else
		{
			*success = false;
		}
	}

	return val;
}

extern "C"	NTSTATUS ChangeHandlePermission10(ULONG32 ActiveId, ULONG32 PassiveId);

typedef struct _EXHANDLE
{
	union
	{
		struct
		{
			ULONG32 TagBits : 2;
			ULONG32 Index : 30;
		};
		HANDLE GenericHandleOverlay;
		uintptr_t Value;
	};
} EXHANDLE, * PEXHANDLE;

typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof)   
{
	union                                    // 3 elements, 0x8 bytes (sizeof)   
	{
		struct                               // 5 elements, 0x8 bytes (sizeof)   
		{
			/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                    
			/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                    
			/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                    
			/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                    
			/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                    
		};
		/*0x000*/         UINT64       Value;
		/*0x000*/         VOID* Ptr;
	};
}EX_PUSH_LOCK_C, * PEX_PUSH_LOCK_C;

typedef struct _HANDLE_TRACE_DB_ENTRY // 4 elements, 0xA0 bytes (sizeof)   
{
	/*0x000*/     struct _CLIENT_ID ClientId;       // 2 elements, 0x10 bytes (sizeof)   
	/*0x010*/     VOID* Handle;
	/*0x018*/     ULONG32      Type;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	/*0x020*/     VOID* StackTrace[16];
}HANDLE_TRACE_DB_ENTRY, * PHANDLE_TRACE_DB_ENTRY;



typedef struct _HANDLE_TRACE_DEBUG_INFO       // 6 elements, 0xF0 bytes (sizeof)   
{
	/*0x000*/     LONG32       RefCount;
	/*0x004*/     ULONG32      TableSize;
	/*0x008*/     ULONG32      BitMaskFlags;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
	/*0x010*/     struct _FAST_MUTEX CloseCompactionLock;   // 5 elements, 0x38 bytes (sizeof)   
	/*0x048*/     ULONG32      CurrentStackIndex;
	/*0x04C*/     UINT8        _PADDING1_[0x4];
	/*0x050*/     struct _HANDLE_TRACE_DB_ENTRY TraceDb[];
}HANDLE_TRACE_DEBUG_INFO, * PHANDLE_TRACE_DEBUG_INFO;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//													Win10 x64
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*typedef union _EXHANDLE
{
	struct
	{
		int TagBits : 2;
		int Index : 30;
	} u;
	void* GenericHandleOverlay;
	ULONG_PTR Value;
} EXHANDLE, * PEXHANDLE;*/


typedef struct _HANDLE_TABLE_ENTRY_WIN10 // Size=16
{
	union
	{
		ULONG_PTR VolatileLowValue; // Size=8 Offset=0
		ULONG_PTR LowValue; // Size=8 Offset=0
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable; // Size=8 Offset=0
		struct
		{
			ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
			ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
			ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
			ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
		};
	};
	union
	{
		ULONG_PTR HighValue; // Size=8 Offset=8
		struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry; // Size=8 Offset=8
		EXHANDLE LeafHandleValue; // Size=8 Offset=8
		struct
		{
			ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
			ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
			ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
		};
	};
	ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY_WIN10, * PHANDLE_TABLE_ENTRY_WIN10;


typedef struct _HANDLE_TABLE_FREE_LIST_WIN10
{
	uintptr_t FreeListLock;
	PHANDLE_TABLE_ENTRY_WIN10 FirstFreeHandleEntry;
	PHANDLE_TABLE_ENTRY_WIN10 lastFreeHandleEntry;
	LONG32 HandleCount;
	ULONG32 HighWaterMark;
	ULONG32 Reserved[8];
} HANDLE_TABLE_FREE_LIST_WIN10, * PHANDLE_TABLE_FREE_LIST_WIN10;


typedef struct _HANDLE_TABLE_WIN10
{
	ULONG32 NextHandleNeedingPool;
	LONG32 ExtraInfoPages;
	uintptr_t TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG32 UniqueProcessId;
	union
	{
		ULONG32 Flags;
		struct
		{
			BOOLEAN StrictFIFO : 1;
			BOOLEAN EnableHandleExceptions : 1;
			BOOLEAN Rundown : 1;
			BOOLEAN Duplicated : 1;
			BOOLEAN RaiseUMExceptionOnInvalidHandleClose : 1;
		};
	};
	uintptr_t HandleContentionEvent;
	uintptr_t HandleTableLock;
	union
	{
		HANDLE_TABLE_FREE_LIST_WIN10 FreeLists[1];
		BOOLEAN ActualEntry[32];
	};
	PVOID DebugInfo;
} HANDLE_TABLE_WIN10, * PHANDLE_TABLE_WIN10;

typedef struct _OBJECT_CREATE_INFORMATION OBJECT_CREATE_INFORMATION, * POBJECT_CREATE_INFORMATION;
typedef struct _OBJECT_HEADER
{
	LONG PointerCount;
	union
	{
		LONG HandleCount;
		PVOID NextToFree;
	};
	EX_PUSH_LOCK Lock;
	UCHAR TypeIndex;
	union
	{
		UCHAR TraceFlags;
		struct
		{
			UCHAR DbgRefTrace : 1;
			UCHAR DbgTracePermanent : 1;
			UCHAR Reserved : 6;
		};
	};
	UCHAR InfoMask;
	union
	{
		UCHAR Flags;
		struct
		{
			UCHAR NewObject : 1;
			UCHAR KernelObject : 1;
			UCHAR KernelOnlyAccess : 1;
			UCHAR ExclusiveObject : 1;
			UCHAR PermanentObject : 1;
			UCHAR DefaultSecurityQuota : 1;
			UCHAR SingleHandleEntry : 1;
			UCHAR DeletedInline : 1;
		};
	};
	union
	{
		POBJECT_CREATE_INFORMATION ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};
	PVOID SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;

PHANDLE_TABLE_ENTRY_WIN10 FindHandleTable(IN PHANDLE_TABLE_WIN10 tablePointer, IN EXHANDLE handleObject)
{
	HANDLE_TABLE_WIN10 HandleTable = ReadVirtualKernel<HANDLE_TABLE_WIN10>(tablePointer);

	uintptr_t TableCode = HandleTable.TableCode & 3;
	if (handleObject.Value >= HandleTable.NextHandleNeedingPool)
	{
		return NULL;
	}

	handleObject.Value &= 0xFFFFFFFFFFFFFFFC;

	if (TableCode != 0)
	{
		if (TableCode == 1)
		{
			uintptr_t tmp1 = ReadVirtualKernel<uintptr_t>((PVOID)(HandleTable.TableCode + 8 * (handleObject.Value >> 11) - 1));
			return (PHANDLE_TABLE_ENTRY_WIN10)(tmp1 + 4 * (handleObject.Value & 0x7FC));
		}
		else
		{
			uintptr_t tmp = handleObject.Value >> 11;
			uintptr_t tmp2 = ReadVirtualKernel<uintptr_t>((PVOID)(HandleTable.TableCode + 8 * (handleObject.Value >> 21) - 2));
			uintptr_t tmp3 = ReadVirtualKernel<uintptr_t>((PVOID)(tmp2 + 8 * (tmp & 0x3FF)));
			return (PHANDLE_TABLE_ENTRY_WIN10)(tmp3 + 4 * (handleObject.Value & 0x7FC));
		}
	}
	else
	{
		return (PHANDLE_TABLE_ENTRY_WIN10)(HandleTable.TableCode + 4 * handleObject.Value);
	}
}

namespace External
{
	NTSTATUS ChangePerms(PVOID entry)
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// Allocate memory
		const ULONG Tag = 'aooP';
		PHANDLE_TABLE_ENTRY_WIN10 ptable = (PHANDLE_TABLE_ENTRY_WIN10)ExAllocatePoolWithTag(NonPagedPool, sizeof(HANDLE_TABLE_WIN10), Tag);

		// Read table
		status = CopyVirtual(ptable, entry, sizeof(HANDLE_TABLE_WIN10));
		if (!NT_SUCCESS(status)) return status;

		// Edit table
		ptable->GrantedAccessBits = 0x1FFFFF;

		// Write table
		status = CopyVirtual(entry, ptable, sizeof(HANDLE_TABLE_WIN10));

		// Free memory
		ExFreePoolWithTag(ptable, Tag);

		return status;
	}

	NTSTATUS FullPerm(HANDLE ActiveId, PEPROCESS peprocess)
	{
		NTSTATUS Status = STATUS_UNSUCCESSFUL;
		PEPROCESS EProcess = NULL;
		uintptr_t Handle = 0;
		PHANDLE_TABLE_ENTRY_WIN10 pEntry = NULL;
		POBJECT_TYPE ObjectType = NULL;
		ULONG64 Object = 0;
		PVOID objectbody = 0;
		
		if (!NT_SUCCESS(PsLookupProcessByProcessId(ActiveId, &EProcess)))
		{
			return Status;
		}

		Log(E("[drv] Trying to elevate handles\n"));
		
		lastProcess = ActiveId;
		lastPeprocess = peprocess;

		for (Handle = 0; Handle < 1000; Handle += HANDLE_VALUE_SIZE)
		{
			static uintptr_t address = 0;
			static RTL_OSVERSIONINFOW version = { sizeof(RTL_OSVERSIONINFOW) };
			if (!version.dwBuildNumber) 
			{
				RtlGetVersion(&version);
			}

			if (version.dwBuildNumber < 19000)
			{
				address = HANDLE_TABLE_ADDRESS_WIN10;
			} else
			{
				address = HANDLE_TABLE_ADDRESS_WIN10_2004;
			}

			pEntry = FindHandleTable(ReadVirtualKernel<PHANDLE_TABLE_WIN10>((PUCHAR)EProcess + address), *(PEXHANDLE)&Handle);
			if (!pEntry)
			{
				Log(E("[drv] Failed to get pentry\n"));
				break;
			}
			HANDLE_TABLE_ENTRY_WIN10 Entry = ReadVirtualKernel<HANDLE_TABLE_ENTRY_WIN10>(pEntry);

			OBJECT_HEADER* pObjectHeader;
			pObjectHeader = (OBJECT_HEADER*)(((Entry.ObjectPointerBits) << 4) | 0xFFFF000000000000);

			if (!pObjectHeader)
				continue;

			OBJECT_HEADER ObjectHeader = ReadVirtualKernel<OBJECT_HEADER>(pObjectHeader);

			if (!ObjectHeader.Body.UseThisFieldToCopy)
				continue;

			objectbody = &pObjectHeader->Body.UseThisFieldToCopy;

			ObjectType = (POBJECT_TYPE)ObGetObjectType(objectbody);
			
			if (ObjectType == *PsProcessType)
			{
				HANDLE curid = PsGetProcessId((PEPROCESS)objectbody);
				//if (curid == PassiveId)
				//{
					Log(E("[drv] Found process handle\n"));
					Status = ChangePerms(pEntry);
					if (NT_SUCCESS(Status))
					{
						Status = STATUS_SUCCESS;
					}
				//}
			}

			if (ObjectType == *PsThreadType)
			{
				HANDLE curid = PsGetThreadId((PETHREAD)objectbody);
				//if (curid == ThreadId)
				//{
					Log(E("[drv] Found thread handle\n"));
					Status = ChangePerms(pEntry);
					if (NT_SUCCESS(Status))
					{
						Status = STATUS_SUCCESS;
					}
				//}
			}
		}

		ObDereferenceObject(EProcess);

		return Status;
	}
};

#pragma warning(pop)