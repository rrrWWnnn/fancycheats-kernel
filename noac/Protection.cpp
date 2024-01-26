#include <ntifs.h>
#include "Protection.h"

void Protection::SetProcessProtection(int pid)
{
	PEPROCESS pProcess = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &pProcess);
	if (!NT_SUCCESS(status))
		return;

	PUCHAR pValue = reinterpret_cast<PUCHAR>(pProcess) + OFFSET_PROTECTION;

	PS_PROTECTION protBuf = { 0 };

	protBuf.Flags.Signer = PsProtectedSignerWinTcb;
	protBuf.Flags.Type = PsProtectedTypeProtected;
	*pValue = protBuf.Level;

	//PMITIGATION_FLAGS pFlags2 = reinterpret_cast<PMITIGATION_FLAGS>(reinterpret_cast<PUCHAR>(pProcess) + OFFSET_FLAGS2);
	//pFlags2->DisableDynamicCode = 1;
}
