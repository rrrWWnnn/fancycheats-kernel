/*
 * Copyright (c) 2020 Samuel Tulach - All rights reserved
 * Unauthorized copying of this project, via any medium is strictly prohibited
 */

#include <ntifs.h>
#include "Xor.h"
#include "KernelImports.h"
#include "Utils.h"
#include "Shared.h"
#include "External.h"
#include "Protection.h"
#include "Patch.h"

static Input* lastInput = nullptr;
static bool shouldExit = false;
static PDEBUG_PRINT_CALLBACK lastCallback = nullptr;
static PEPROCESS lastPeprocess = nullptr;

//#define TARGET_IRQL APC_LEVEL
#define TARGET_IRQL PASSIVE_LEVEL

/*
 * Windows PatchGuard does not like it when there is an input
 * in the table that is not in legitimate driver
 * We can unregister it and it will be fine
 * It has to be done in another thread since for some unknown reason
 * that I am too lazy to investigate you are not able to do so from
 * debug callback itself
 */
void UnregisterCallback(void*)
{
	// Same pointer just with false will unregister it
	DbgSetDebugPrintCallback(lastCallback, false);

	// Disable filers again
	Utils::SetDebugLevel(DPFLTR_KTM_ID, false);

	// Restore the hook
	Patch::RestoreJmpTo();
}

/*
 * Debug callback itself
 * (see DbgSetDebugPrintCallback in EntryPoint)
 */
void DebugPrintCallback(PANSI_STRING inputString, ULONG, ULONG)
{
	// Don't do anything if the driver should exit
	// (for example when client exits)
	if (shouldExit)
		return;
	
	// Check if it is a log coming from our driver
	// If yes, just return because we don't want infinite loop
	// Also it would be nice not to use it at all btw
	if (Utils::Contains(inputString->Buffer, const_cast<char*>(E("[drv]")), inputString->Length))
		return;

	// Print debug info so we know this callback has been called
	Log(E("[drv] Callback called\n"));

	// We want to trigger only on specific message which is from target driver
	// KTM:  TmCommitTransactionExt for tx d688eaf0
	if (!Utils::Contains(inputString->Buffer, const_cast<char*>(E("TmCommitTransactionExt")), inputString->Length))
		return;

	// Print debug info so we know that we got the right driver
	Log(E("[drv] Filter success\n"));
	
	// Defined on top because MSVC has psychical issues from
	// goto and variable definitions
	PEPROCESS clientProcess = nullptr;
	NTSTATUS status;
	KIRQL originalLevel;

	// Some Windows functions will just strait up fail if the
	// irql are not set properly
	originalLevel = KeGetCurrentIrql();
	if (originalLevel > TARGET_IRQL)
	{
		KIRQL desiredLevel = TARGET_IRQL;
		KeLowerIrql(desiredLevel);
	}
	
	// Check if client process is running and get it's EPROCESS pointer
	// If the PEPROCESS does not match, unregister the callback
	// Also check if the process name is the same
	status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(lastInput->Pid), &clientProcess);
	NTSTATUS exitCode = PsGetProcessExitStatus(clientProcess);
	if (!(NT_SUCCESS(status) && clientProcess == lastPeprocess && exitCode == 259)) // 259 == STILL_ACTIVE
	{
		// We need to know if the driver is not being unloaded too early
		Log(E("[drv] Callback unregistered\n"));

		// Has to be run in new thread
		// because thats how Windows works
		HANDLE dummy = nullptr;
		PsCreateSystemThread(
			&dummy,
			GENERIC_ALL,
			nullptr,
			nullptr,
			nullptr,
			UnregisterCallback,
			nullptr
		);

		// Client has exited so we don't need the driver anymore
		shouldExit = true;

		goto end;
	}

	// Run our main driver logic
	External::FullPerm(reinterpret_cast<HANDLE>(lastInput->Pid), lastPeprocess);

end:
	// Clean up memory
	if (clientProcess)
		ObDereferenceObject(clientProcess);

	// Reset irql
	if (originalLevel > TARGET_IRQL)
	{
		KIRQL currentLevel = KeGetCurrentIrql();
		KeRaiseIrql(originalLevel, &currentLevel);
	}
}

/*
 * Custom driver entry that needs custom input parameters
 * Supply the input struct from driver manual mapper
 */
extern "C" NTSTATUS EntryPoint(Input* input, void*)
{
	if (!input)
		return STATUS_INVALID_PARAMETER_1;

	if (input->Magic != MAGIC)
		return STATUS_INVALID_PARAMETER_2;

	// Defining on top again because MSVC nice goto implementation
	UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
	NTSTATUS status = STATUS_SUCCESS;
	
	// Copy the input struct to local buffer
	// It has to be non-paged to stop weird behaviour
	lastInput = static_cast<Input*>(ExAllocatePool(NonPagedPool, sizeof(Input)));
	memcpy(lastInput, input, sizeof(Input));

	// Print confirmation text that the driver is loaded
	DbgPrintEx(0, 0, E("[drv] Loaded. Build from %s. Using client process on PID %i. Irql: %i."), __DATE__, lastInput->Pid, KeGetCurrentIrql());

	// Change mode to kernel-mode so we can change the filters and shit
	Utils::ChangeMode(KernelMode);

	// Change the filters so we can actually use the target driver prints
	Utils::SetDebugLevel(DPFLTR_KTM_ID, true);

	// Hook a legit driver to basically bypass PatchGuard callback protection
	PVOID driverHooked = Patch::DrvObj(driverName, static_cast<PVOID>(DebugPrintCallback));
	if (!driverHooked)
	{
		status = STATUS_UNSUCCESSFUL;
		goto exit;
	}	

	// Register callback that get's called every time some driver
	// uses DbgPrint or it's equivalent
	lastCallback = reinterpret_cast<PDEBUG_PRINT_CALLBACK>(driverHooked);
	status = DbgSetDebugPrintCallback(lastCallback, true);
	if (!NT_SUCCESS(status))
		goto exit;

	// Get the client PEPROCESS because apparently
	// using just plain PID is not a good idea
	status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(lastInput->Pid), &lastPeprocess);

exit:
	// Change the mode back to prevent some random bullshit
	Utils::ChangeMode(UserMode);

	return status;
}