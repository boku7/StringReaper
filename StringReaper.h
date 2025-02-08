#include <windows.h>
#include "beacon.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI BOOL WINAPI KERNEL32$SetNamedPipeHandleState(HANDLE  hNamedPipe, LPDWORD lpMode, LPDWORD lpMaxCollectionCount, LPDWORD lpCollectDataTimeout);
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);
WINBASEAPI BOOL WINAPI KERNEL32$WaitNamedPipeA(LPCSTR lpNamedPipeName, DWORD nTimeOut);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI void* WINAPI MSVCRT$free(void*);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);
WINBASEAPI void WINAPI MSVCRT$srand(int initial);
WINBASEAPI int WINAPI MSVCRT$rand();
WINBASEAPI time_t WINAPI MSVCRT$time(time_t* time);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI void * WINAPI KERNEL32$AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
WINBASEAPI void * WINAPI KERNEL32$RemoveVectoredExceptionHandler(PVOID Handle);
WINBASEAPI VOID WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size) (ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

#define Error   0x42
#define noError 0x41
#define XORKEY 0xBC
#define ADD(Type, A, B) (Type)((unsigned __int64) A + B)
#define DREF32(VA)*(unsigned long*)(VA)
#define STATUS_SUCCESS 0x0

void* getDllBase(void*);
void xorc(unsigned __int64 length, unsigned char * buff, unsigned char maskkey);
void* hash2Address(unsigned __int64 hash, void* dllBase, void* AddressTable, void* NameTable, void* OrdinalTable);
unsigned char* hasher(int stringLen, char* string);
unsigned __int64 xstrlen(char* string);
unsigned __int64 xChkStrlen(char* string);
void downloadFile(char* fileName, int downloadFileNameLength, char* returnData, int fileSize);


void* getUnicodeStrLen(void* envStrAddr) {
    void* unicodeStrLen = NULL;
    __asm__(
        "mov rax, %[envStrAddr] \n"
        "xor rbx, rbx \n" // RBX is our 0x00 null to compare the string position too
        "xor rcx, rcx \n" // RCX is our string length counter
    "check: \n"
        "inc rcx \n"
        "cmp bl, [rax + rcx] \n"
        "jne check \n"
        "inc rcx \n" 
        "cmp bl, [rax + rcx] \n"
        "jne check \n"
        "mov %[unicodeStrLen], rcx \n"
	:[unicodeStrLen] "=r" (unicodeStrLen)
	:[envStrAddr] "r" (envStrAddr)
    );
    return unicodeStrLen;
}

__asm__(
"getDllBase: \n"
    "mov rbx, gs:[0x60] \n"         // ProcessEnvironmentBlock // GS = TEB
    "mov rbx, [rbx+0x18] \n"        // _PEB_LDR_DATA
    "mov rbx, [rbx+0x20] \n"        // InMemoryOrderModuleList - First Entry (probably the host PE File)
    "mov r11, rbx \n"
"crawl: \n"
    "mov rdx, [rbx+0x50] \n"        // BaseDllName Buffer
    "push rbx \n"                   // just to save its value
    "call cmpwstrings \n"
    "pop rbx \n"
    "cmp rax, 0x1 \n"
    "je found \n"
    "mov rbx, [rbx] \n"             // InMemoryOrderLinks Next Entry
    "cmp r11, [rbx] \n"             // Are we back at the same entry in the list?
    "jne crawl \n"
    "xor rax, rax \n"               // DLL is not in InMemoryOrderModuleList, return NULL
    "jmp end \n"
"found: \n"
    "mov rax, [rbx+0x20] \n"        // DllBase Address in process memory
"end: \n"
    "ret \n"
"makeWideString: \n"
    "xor rax, rax \n"               // counter
"makews: \n"
    "add rdx, rax \n"               // add counter
    "add rcx, rax \n"               // add counter
    "add rcx, rax \n"               // add counter again
    "dec rcx \n"                    // decrease by 1
    "mov bl, 0x0 \n"                // write nulbyte
    "mov [rcx], bl \n"
    "inc rcx \n"                    // increase again
    "mov bl, [rdx] \n"
    "mov [rcx], bl \n"              // copy char
    "cmp bl, 0x0 \n"
    "je madews\n"
    "inc rax \n"
    "jmp makews \n"
"madews: \n"
    "ret \n"
"cmpwstrings: \n"
    "xor rax, rax \n"               // counter
"cmpchar: \n"
    "mov sil, [rcx+rax] \n"         // load char
    "cmp sil, 0x0 \n"
    "je nolow1 \n"
    "or sil, 0x20 \n"               // make lower case
"nolow1: \n"
    "mov dil, [rdx+rax] \n"         // load char
    "cmp dil, 0x0 \n"
    "je nolow2 \n"
    "or dil, 0x20 \n"               // make lower case
"nolow2: \n"
    "cmp sil, dil \n"               // compare
    "jne nonequal \n"
    "cmp sil, 0x0 \n"               // end of string?
    "je equal \n"
    "inc rax \n"
    "inc rax \n"
    "jmp cmpchar \n"
"nonequal: \n"
    "mov rax, 0x0 \n"               // return "false"
    "ret \n"
"equal: \n"
    "mov rax, 0x1 \n"               // return "true"
    "ret \n"
);

typedef struct Export {
  void* Directory;
  void* AddressTable;
  void* NameTable;
  void* OrdinalTable;
}Export;

typedef struct DL {
  void* dllBase;
  void* NewExeHeader;
  unsigned __int64 size;
  void* OptionalHeader;
  void* NthSection;
  unsigned short NumberOfSections;
  void* EntryPoint;
  void* TextSection;
  unsigned __int64 TextSectionSize;
  Export Export;
}DL;
typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOL       Initialized;
    LPVOID     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _UNICODE_STRING
{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG  uLength;
    HANDLE  hRootDirectory;
    PVOID   pObjectName;
    ULONG  uAttributes;
    PVOID  pSecurityDescriptor;
    PVOID  pSecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE  pid;
    HANDLE  UniqueThread;

} CLIENT_ID, * PCLIENT_ID;

typedef enum _PROCESSINFOCLASS {
  ProcessBasicInformation = 0,
  ProcessDebugPort = 7,
  ProcessWow64Information = 26,
  ProcessImageFileName = 27,
  ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef long(NTAPI* tNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PVOID NumberOfBytesRead);
typedef long(NTAPI* tNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef long(NTAPI* tNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef long(NTAPI* tNtClose)(HANDLE Handle);
typedef long(NTAPI* tNtQueryVirtualMemory)( HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

typedef struct ntapis {
    tNtReadVirtualMemory NtReadVirtualMemory;
    tNtOpenProcess NtOpenProcess;
    tNtQueryInformationProcess NtQueryInformationProcess;
    tNtClose NtClose;
    tNtQueryVirtualMemory NtQueryVirtualMemory;
}ntapis;

void    Memcpy(void * destination, void * source, unsigned int num);


__asm__(
        // void* hash2Address(qword hash,void* dllBase, void* AddressTable, void* NameTable, void* OrdinalTable);
//                           RCX         RDX             R8                R9              [RSP+0x28]
"hash2Address: \n"
    "mov [rsp+0x08], rcx \n"   // hash
    "mov [rsp+0x10], rdx \n"   // dllBase 
    "mov [rsp+0x18], r8  \n"   // AddressTable 
    "mov [rsp+0x20], r9  \n"   // NameTable 
    "xor r11, r11        \n"
"lFindSym:               \n"
    "xor rcx, rcx        \n"   // Clear RDI for setting up string name retrieval
    "mov ecx, [r9+r11*4] \n"   // RVA NameString = [&NamePointerTable + (Counter * 4)]
    "add rcx, [rsp+0x10] \n"   // &NameString    = RVA NameString + &module.dll
    "mov r12, rcx        \n"   // Save &NameString to R12
    "call xstrlen        \n"   // xstrlen("NameString")
    "mov rcx, rax        \n"   // rcx = strlen
    "mov rdx, r12        \n"   // rdx = &NameString
    "call hasher         \n"   // rax = hasher(qword strlen, &NameString)
    "mov rdx, [rsp+0x08] \n"   // rdx = name hash
    "cmp rax, rdx        \n"   // import name hash == our hash ?
    "je FoundSym         \n"   // If match then we found the API string. Now we need to find the Address of the API
    "inc r11             \n"   // Increment to check if the next name matches
    "jmp short lFindSym  \n"   // Jump back to start of loop
"FoundSym:               \n"
    "mov rcx, [rsp+0x28] \n"   // &OrdinalTable
    "xor rax, rax        \n"
    "mov ax, [rcx+r11*2] \n"   // [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
    "mov eax, [r8+rax*4] \n"   // RVA API = [&AddressTable + API OrdinalNumber]
    "add rax, [rsp+0x10] \n"   // module.<API> = RVA module.<API> + module.dll BaseAddress
    "sub rcx, rax        \n"   // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
    "jns notForwarder    \n"   // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
    "xor rax, rax        \n"   // If forwarder, return 0x0 and exit
"notForwarder:           \n"
    "ret                 \n"

// Clobbers: RAX RCX
"xstrlen:\n"              // Get the string length for the string
    "push r9\n"           // Save register value
    "mov rax, rcx\n"      // RAX = string address
    "mov rcx, 0x0\n"    
"ctLoop:\n" 
    "mov r9, 0x0\n" 
    "cmp r9b, [rax]\n"    // are we at the null terminator for the string?
    "je fLen\n" 
    "inc cl\n"            // increment the name string length counter
    "inc rax\n"           // move to the next char of the string
    "jmp short ctLoop\n" 
"fLen:\n" 
    "mov rax, rcx\n"  
    "pop r9\n"            // restore register
    "ret\n"  

// Clobbers: RAX RCX
"xChkStrlen:\n"              // Get the string length for the string
    "push r9\n"           // Save register value
    "mov rax, rcx\n"      // RAX = string address
    "mov rcx, 0x0\n"    
"xChkStrLoop:\n" 
    "mov r9, 0x0\n" 
    "cmp r9b, [rax]\n"    // are we at the null terminator for the string?
    "je xChkStrfLen\n" 
   // "mov dl, 0x30 \n"
   // "cmp r9b, dl \n "     // if less ascii 0x30 then end
   // "jl xChkStrfLen\n" 
    "mov dl, 0x7A \n"
    "cmp r9b, dl \n "     // if greater than ascii 0x7A then end
    "jg notAString\n" 
    "inc cl\n"            // increment the name string length counter
    "inc rax\n"           // move to the next char of the string
    "jmp short xChkStrLoop\n" 
"notAString: \n"
    "mov rcx, 0x0\n"
"xChkStrfLen:\n" 
    "mov rax, rcx\n"  
    "pop r9\n"            // restore register
    "ret\n"  



// Clobbers: RAX RDX RCX
"hasher: \n"
      "xor rax, rax \n"
 "h1loop: \n"
      "add al, [rdx] \n"
      "xor al, 0x70 \n"
      "rol rax, 0x8 \n"
      "inc rdx \n"
      "dec rcx \n"
      "test cl, cl \n"
      "jnz h1loop \n"
      "ret \n"

"Memcpy: \n"  // RAX, RBX, RCX, RDX, R8
    "xor r10, r10 \n"
    "test r8, r8 \n"                // check if r8 = 0
    "jne copy1 \n"                  // if r8 == 0, ret
    "ret \n"                        // Return to caller
"copy1: \n"
    "dec r8 \n"                     // Decrement the counter
    "mov r10b, [rdx] \n"              // Load the next byte to write
    "mov [rcx], r10b \n"              // write the byte
    "inc rdx \n"                    // move rdx to next byte of source
    "inc rcx \n"                    // move rcx to next byte of destination
    "test r8, r8 \n"                // check if r8 = 0
    "jne copy1 \n"                  // if r8 != 0, then write next byte via loop
    "ret \n"                        // Return to Memcpy()

);


#define STATUS_BUFFER_TOO_SMALL 0xC0000004

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                  Flags;
  USHORT                  Length;
  ULONG                   TimeStamp;
  UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
  UNICODE_STRING DosPath;
  PVOID Handle;
} CURDIR, * PCURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
  ULONG MaximumLength;
  ULONG Length;

  ULONG Flags;
  ULONG DebugFlags;

  HANDLE ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StandardInput;
  HANDLE StandardOutput;
  HANDLE StandardError;

  CURDIR CurrentDirectory;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  PVOID Environment;

  ULONG StartingX;
  ULONG StartingY;
  ULONG CountX;
  ULONG CountY;
  ULONG CountCharsX;
  ULONG CountCharsY;
  ULONG FillAttribute;

  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING DesktopInfo;
  UNICODE_STRING ShellInfo;
  UNICODE_STRING RuntimeData;
  RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

  ULONG EnvironmentSize;
  ULONG EnvironmentVersion;
  PVOID PackageDependencyData;
  ULONG ProcessGroupId;
  ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef
VOID
(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
  VOID
  );

typedef struct _PEB {
  unsigned char InheritedAddressSpace;
  unsigned char ReadImageFileExecOptions;
  unsigned char BeingDebugged;
  unsigned char BitField;
  unsigned char Padding;
  void* Mutant;
  void* ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  void* SubSystemData;
  void* ProcessHeap;
  void* FastPebLock;
  void* AtlThunkSListPtr;
  void* IFEOKey;
  void* ReservedBits0;
  void* KernelCallbackTable;
  unsigned long Reserved8;
  unsigned long AtlThunkSListPtr32;
  void* ApiSetMap;
  unsigned long TlsExpansionCounter;
  void* TlsBitmap;
  unsigned long TlsBitmapBits[2];
  void* ReadOnlySharedMemoryBase;
  void* SharedData;
  PVOID* ReadOnlyStaticServerData;
  void* AnsiCodePageData;
  void* OemCodePageData;
  void* UnicodeCaseTableData;
  unsigned long NumberOfProcessors;
  unsigned long NtGlobalFlag;
  void* CriticalSectionTimeout;
  unsigned long* HeapSegmentReserve;
  unsigned long* HeapSegmentCommit;
  unsigned long* HeapDeCommitTotalFreeThreshold;
  unsigned long* HeapDeCommitFreeBlockThreshold;
  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID* ProcessHeaps;
  void* GdiSharedHandleTable;
  void* ProcessStarterHelper;
  ULONG GdiDCAttributeList;
  void* LoaderLock;
  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  USHORT OSBuildNumber;
  WORD wOSCSDVersion;
  DWORD dwOSPlatformId;
  DWORD dwImageSubsystem;
  DWORD dwImageSubsystemMajorVersion;
  DWORD dwImageSubsystemMinorVersion;
  DWORD dwImageProcessAffinityMask;
  DWORD dwGdiHandleBuffer[34];
  void* lpPostProcessInitRoutine;
  void* lpTlsExpansionBitmap;
  DWORD dwTlsExpansionBitmapBits[32];
  DWORD dwSessionId;
  void* liAppCompatFlags;
  void* liAppCompatFlagsUser;
  LPVOID lppShimData;
  LPVOID lpAppCompatInfo;
  UNICODE_STRING usCSDVersion;
  LPVOID lpActivationContextData;
  LPVOID lpProcessAssemblyStorageMap;
  LPVOID lpSystemDefaultActivationContextData;
  LPVOID lpSystemAssemblyStorageMap;
  DWORD dwMinimumStackCommit;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
  PVOID Reserved1;
  PPEB PebBaseAddress;
  PVOID Reserved2[2];
  ULONG_PTR UniqueProcessId;
  PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

DWORD xstrcmp(PVOID string1, PVOID string2, unsigned __int64 Count);

__asm__(
"xstrcmp:\n"
    "push rsi \n" // save
    "push rdi \n" // save
    "mov rdi, rcx\n"          // RDI = string1
    "mov rsi, rdx\n"          // RSI = string2
    "mov rcx, r8\n"           // RCX = stringsize
    "repe cmpsb\n"            // Compare strings at RDI & RSI
  "je stringmatch\n"        // If match then we found the API string. Now we need to find the Address of the API
    "xor rax, rax\n"          // If does not match return -1
    "or rax, 0x01\n"           // RAX = -1
  "jmp endstrcmp \n"
"stringmatch:\n"
    "xor rax, rax\n"          // If string match return 0
"endstrcmp: \n"
    "pop rdi \n" // restore
    "pop rsi \n" // restore
    "ret\n"
);