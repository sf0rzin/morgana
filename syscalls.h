// Indirect syscall layer (x64, Windows 10/11) - educational demo
// Technique: resolve ntdll function address, locate the `syscall`
// instruction past the (hooked) prologue, then jmp to it through a
// small runtime-built stub (mov r10,rcx / mov eax,<num> / jmp).
#pragma once
#include <windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef _UNICODE_STRING_DEFINED
#ifndef __UNICODE_STRING_DEFINED
#define __UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif
#endif

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#define SYSCALL_STUB_SIZE 32
#define SYSCALL_MAX 8

namespace sc {

bool init();

LONG NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                             PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
LONG NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                            ULONG NewProtect, PULONG OldProtect);
LONG NtCreateFile(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                  PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize,
                  ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition,
                  ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
LONG NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
                 PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
                 PLARGE_INTEGER ByteOffset, PULONG Key);
LONG NtClose(HANDLE Handle);

}
