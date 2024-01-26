#pragma once

class Patch
{
private:
	static PVOID GetShellCode(uintptr_t address);
public:
	static void JmpTo(PVOID function, PVOID target);
	static void RestoreJmpTo();
	static PVOID DrvObj(UNICODE_STRING name, PVOID target);
};
