#include <ntdef.h>
#include <windows.h>

#ifndef _TYPES_H
#define _TYPES_H
typedef unsigned long long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

typedef long long __s64;
typedef int __s32;
typedef short __s16;
typedef char __s8;

typedef struct {
    __u16 Length;
    __u16 MaximumLength;
    __u16 *Buffer;
} _UNICODE_STRING_;

typedef struct {
    LPVOID CurrentSEH;
    LPVOID StackBase;
    LPVOID StackLimit;
    LPVOID SubSystemTib;
    LPVOID FiberData;
    LPVOID ArbitraryDataSlot;
    LPVOID TebAddress;
    LPVOID EnvironmentPointer;
    LPVOID ProcessID;
    LPVOID ThreadID;
    LPVOID RpcHandle;
    LPVOID TlsAddress;
    LPVOID PebAddress;
    DWORD LastError;
    DWORD CriticalSectionsCount;
    LPVOID CsrClientThreadAddre;
    LPVOID Win32ThreadInfo;
    BYTE Win32ClientInfo[124];
    LPVOID ReservedWow64;
    DWORD CurrentLocale;
    DWORD FpSwStatusReg;
    BYTE ReservedOS[216];
} _TEB_;

typedef struct {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    DWORD CrossProcessFlags;
    BYTE Padding1[4];
    PVOID KernelCallbackTable;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    PVOID ApiSetMap;
    DWORD TlsExpansionCounter;
    BYTE Padding2[4];
    PVOID TlsBitmap;
    DWORD TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    DWORD NtGlobalFlag;
    INT64 CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
} _PEB_;

typedef struct {
    _UNICODE_STRING_ WindowsDirectory;
    _UNICODE_STRING_ WindowsSystemDirectory;
    _UNICODE_STRING_ NamedObjectDirectory;
    USHORT WindowsMajorVersion;
    USHORT WindowsMinorVersion;
    USHORT BuildNumber;
} BASE_STATIC_SERVER_DATA;

typedef struct __LIST_ENTRY_ {
    struct __LIST_ENTRY_ *Flink;
    struct __LIST_ENTRY_ *Blink;
} _LIST_ENTRY_;

typedef struct {
    DWORD Length;
    DWORD Initialized;
    LPVOID SsHandle;
    _LIST_ENTRY_ InLoadOrderModuleList;
    _LIST_ENTRY_ InMemoryOrderModuleList;
    _LIST_ENTRY_ InInitializationOrderModuleList;
    LPVOID EntryInProgress;
    LPVOID ShutdownInProgress;
    LPVOID selfShutdownThreadId;
} _PEB_LDR_DATA_;

typedef struct {
    _LIST_ENTRY_ InLoadOrderLinks;
    _LIST_ENTRY_ InMemoryOrderLinks;
    _LIST_ENTRY_ InInitializationOrderLinks;

    PVOID DllBase;
    PVOID EntryPoint;
    UINT SizeOfImage;

    _UNICODE_STRING_ FullDllName;
    _UNICODE_STRING_ BaseDllName;

    UINT Flags;
    __u16 ObsoleteLoadCount;
    __u16 TlsIndex;

    _LIST_ENTRY_ HashLinks;
    UINT TimeDateStamp;

    PVOID EntryPointActivationContext;
    PVOID Lock;
    PVOID DdagNode;

    _LIST_ENTRY_ NodeModuleLink;
    PVOID LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;

    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;

    PVOID OriginalBase;
    __u64 LoadTime;
    UINT BaseNameHashValue;
    UINT LoadReason;
    PVOID ImplicitPathOptions;
    PVOID ReferenceCount;
    PVOID DependentLoadFlags;
    __u8 SigningLevel;
} _LDR_DATA_TABLE_ENTRY_;

typedef struct {
    _LIST_ENTRY_ list;
    _LDR_DATA_TABLE_ENTRY_ e;
} _LIST_LDR_DATA_TABLE_ENTRY_;

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef PROCESSOR_FEATURE_MAX
#define PROCESSOR_FEATURE_MAX 64
#endif

typedef struct {
    UINT LowPart;
    INT High1Time;
    INT High2Time;
} _KSYSTEM_TIME_;

typedef struct {
    UINT TickCountLowDeprecated;
    UINT TickCountMultiplier;
    _KSYSTEM_TIME_ InterruptTime;
    _KSYSTEM_TIME_ SystemTime;
    _KSYSTEM_TIME_ TimeZoneBias;
    __u16 ImageNumberLow;
    __u16 ImageNumberHigh;
    WCHAR NtSystemRoot[MAX_PATH];
    UINT MaxStackTraceDepth;
    UINT CryptoExponent;
    UINT TimeZoneId;
    UINT LargePageMinimum;
    UINT Reserved2[7];
    UINT NtProductType;
    UINT ProductTypeIsValid;
    UINT NtMajorVersion;
    UINT NtMinorVersion;
    __u8 ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    UINT Reserved1;
    UINT Reserved3;
    UINT TimeSlip;
    UINT AlternativeArchitecture;
    UINT AltArchitecturePad;
    ULONGLONG SystemExpirationDate;
    UINT SuiteMask;
    __u8 KdDebuggerEnabled;
    __u8 NXSupportPolicy;
    UINT ActiveConsoleId;
    UINT DismountCount;
    UINT ComPlusPackage;
    UINT LastSystemRITEventTickCount;
    UINT NumberOfPhysicalPages;
    __u8 SafeBootMode;
    __u8 TscQpcData;
    __u8 TscQpcFlags;
    __u8 TscQpcPad[3];
    __u8 SharedDataFlags;
    __u8 DataFlagsPad[3];
    __u8 TestRetInstruction;
    __u8 _padding0[0x2F8];
} _KUSER_SHARED_DATA_;
#endif
