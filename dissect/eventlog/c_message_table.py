from __future__ import annotations

from dissect.cstruct import cstruct

message_table_def = """
/* ── PE header structures ─────────────────────────────────────────── */
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES  16
#define IMAGE_SIZEOF_SHORT_NAME           8
#define IMAGE_DIRECTORY_ENTRY_RESOURCE    2
#define RT_MESSAGETABLE                   11

typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    LONG  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_SECTION_HEADER {
    char   Name[IMAGE_SIZEOF_SHORT_NAME];
    ULONG  VirtualSize;
    ULONG  VirtualAddress;
    ULONG  SizeOfRawData;
    ULONG  PointerToRawData;
    ULONG  PointerToRelocations;
    ULONG  PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG  Characteristics;
} IMAGE_SECTION_HEADER;

/* ── PE resource directory structures ────────────────────────────── */

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    WORD  NumberOfNamedEntries;
    WORD  NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY;

/* Each entry is two DWORDs; the high bit of each encodes whether the
   value is an offset-to-name / offset-to-subdirectory (bit=1) or a
   plain integer ID / data-entry offset (bit=0).  We read them as raw
   DWORD pairs and handle the masking in Python. */
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    DWORD NameOffsetOrId;
    DWORD DataEntryOffsetOrSubdirectory;
} IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY;

/* ── RT_MESSAGETABLE structures ───────────────────────────────────── */

typedef struct _MESSAGE_RESOURCE_BLOCK {
    DWORD LowId;
    DWORD HighId;
    DWORD OffsetToEntries;
} MESSAGE_RESOURCE_BLOCK;

typedef struct _MESSAGE_RESOURCE_DATA {
    DWORD                NumberOfBlocks;
    MESSAGE_RESOURCE_BLOCK Blocks[NumberOfBlocks];
} MESSAGE_RESOURCE_DATA;

/* Entry header only – the variable-length Text field is read
   separately using the Length value. */
typedef struct _MESSAGE_RESOURCE_ENTRY {
    WORD Length;
    WORD Flags;
} MESSAGE_RESOURCE_ENTRY;
"""

c_message_table = cstruct().load(message_table_def)

# Convenience aliases
RT_MESSAGETABLE = c_message_table.RT_MESSAGETABLE
IMAGE_DIRECTORY_ENTRY_RESOURCE = c_message_table.IMAGE_DIRECTORY_ENTRY_RESOURCE

# Magic constants for optional header detection
_PE_MAGIC_PE32 = 0x010B
_PE_MAGIC_PE32_PLUS = 0x020B

# RT_MESSAGETABLE entry flag: text is Unicode (UTF-16LE) when set
_MESSAGE_RESOURCE_UNICODE = 0x0001

# Bitmasks for resource directory entry fields
_RSRC_NAME_IS_STRING = 0x80000000
_RSRC_OFFSET_IS_SUBDIR = 0x80000000
_RSRC_OFFSET_MASK = 0x7FFFFFFF
