#pragma once

/*
 * This file defines required functions that are exported by ntoskrnl
 * but not included in WDK
 */

extern "C"
{
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS process);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS sourceProcess, PVOID sourceAddress, PEPROCESS targetProcess, PVOID targetAddress, SIZE_T bufferSize, KPROCESSOR_MODE previousMode, PSIZE_T returnSize);
}

