#include <stdint.h>
#include "defs.h"

#define SEED 0xDEADDEAD
#define HASH(API)(crc32b((uint8_t *)API))

#define NtClose_CRC32b                      0xf78fd98f
#define NtReadFile_CRC32b                   0xab569438
#define LdrLoadDll_CRC32b                   0x43638559
#define NtCreateFile_CRC32b                 0x962c4683
#define NtFreeVirtualMemory_CRC32b          0xf29625d3
#define NtReadVirtualMemory_CRC32b          0x58bdb7be
#define RtlInitUnicodeString_CRC32b         0xe17f353f
#define NtWriteVirtualMemory_CRC32b         0xcf14127c
#define NtQueryInformationFile_CRC32b       0xb54956cb
#define NtProtectVirtualMemory_CRC32b       0x357d60b3
#define LdrGetProcedureAddress_CRC32b       0x3b93e684
#define RtlMultiByteToUnicodeN_CRC32b       0xaba11095
#define NtAllocateVirtualMemory_CRC32b      0xec50426f
#define NtFlushInstructionCache_CRC32b      0xc5f7ca5e

extern void *get_ntdll();

void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash);

