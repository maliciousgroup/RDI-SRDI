#include "structs.h"

#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }
#define FILL_STRING(string, buffer)       \
	string.Length = (USHORT)sl(buffer);   \
	string.MaximumLength = string.Length; \
	string.Buffer = buffer

typedef VOID     (__stdcall *PIO_APC_ROUTINE)(PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,ULONG Reserved);
typedef VOID     (__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);

typedef NTSTATUS (__stdcall *NtClose_t)(HANDLE);
typedef NTSTATUS (__stdcall *RtlMultiByteToUnicodeN_t)(PWCH UnicodeString,ULONG MaxBytesInUnicodeString,PULONG BytesInUnicodeString,PCSTR MultiByteString,ULONG BytesInMultiByteString);
typedef NTSTATUS (__stdcall *NtReadFile_t)(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
typedef NTSTATUS (__stdcall *LdrLoadDll_t)(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
typedef NTSTATUS (__stdcall *LdrGetProcedureAddress_t)(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, PVOID* ProcedureAddress);
typedef NTSTATUS (__stdcall *NtCreateFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (__stdcall *NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, DWORD NewProtect, PULONG OldProtect);
typedef NTSTATUS (__stdcall *NtFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS (__stdcall *NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,PULONG NumberOfBytesWritten);
typedef NTSTATUS (__stdcall *NtReadVirtualMemory_t)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,SIZE_T BufferSize,PSIZE_T NumberOfBytesRead);
typedef NTSTATUS (__stdcall *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
typedef NTSTATUS (__stdcall *NtQueryInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
