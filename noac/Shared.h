#pragma once

typedef struct _Input
{
	int Magic;
	int Pid;
} Input;

constexpr auto MAGIC = 0xDEAD;

//#define ENABLE_DEBUG_LOGS 1

#ifdef ENABLE_DEBUG_LOGS
#define Log(...) DbgPrintEx(0, 0, __VA_ARGS__)
#else
#define Log(...)
#endif