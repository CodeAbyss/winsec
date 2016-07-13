



// Not really suitable for using just yet...
// Odzhan

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <sfc.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "sfc.lib")
#pragma comment (lib, "udis86.lib")
#pragma comment (lib, "version.lib")
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "wintrust.lib")

#define  WIN_CERT_TYPE_EFI_PKCS115          UINT16_C(0x0ef0)
#define  WIN_CERT_TYPE_EFI_GUID             UINT16_C(0x0ef1)

PBYTE img=NULL;
ULONGLONG img_base;
HANDLE hFile, hMap;
LPBYTE lpAddress;
DWORD cpu_arch, flags;

#define PD_OPT_ARCH      1<<1
#define PD_OPT_BOUND     1<<2
#define PD_OPT_SECURITY  1<<3   // "certs",      "security directory"},
#define PD_OPT_COM       1<<4   // "com",        "com directory"
#define PD_OPT_DEBUG     1<<5   // "debug",      "debug directory"},
#define PD_OPT_DELAY     1<<6
#define PD_OPT_DISASM    1<<7   // "disasm",     "disassemble executable sections"},
#define PD_OPT_DOS_HDR   1<<8   // "dos",        "dos header"},
#define PD_OPT_EXCEPT    1<<9   // "except",     "exception directory"
#define PD_OPT_EXPORTS   1<<10   // "exports",    "export directory"},
#define PD_OPT_EXTRACT   1<<11   // "extract",    "extract sections and resources to file"},
#define PD_OPT_FILE_HDR  1<<12   // "file",       "file header"},
#define PD_OPT_GBL       1<<13
#define PD_OPT_ALL_HDR   1<<14   // "headers",    "dos, file, optional and section headers"},
#define PD_OPT_HEX       1<<15   // "hex",        "display hexadecimal values for data and resources"},
#define PD_OPT_IAT       1<<16
#define PD_OPT_IMPORTS   1<<17  // "imports",    "import directory"},
#define PD_OPT_LOAD_CFG  1<<18  // "loadconfig", "load configuration"},
#define PD_OPT_OPT_HDR   1<<19  // "optional",   "optional header"},
#define PD_OPT_RELOC     1<<20  // "optional",   "optional header"},
#define PD_OPT_RESOURCE  1<<21  // "resource",   "resource directory"},
#define PD_OPT_SECTION   1<<22  // "section",    "sections"},
#define PD_OPT_STRINGS   1<<23  // "strings",    "dump strings"},
#define PD_OPT_TLS       1<<24  // "tls",        "tls directory"},
#define PD_OPT_VERSION   1<<25  // "version",    "version information"},
#define PD_OPT_VERIFY    1<<26  // "verify",     "verify if signed"},
#define PD_OPT_ALL       1<<27  // "all",        "dump all"
#define PD_OPT_SFC       1<<28  // "sfc",        "system file checker"  
#define PD_OPT_MD5       1<<29  // "md5",        "generate md5 of file"
#define PD_OPT_SHA1      1<<30  // "sha1",       "generate sha1 of file"
#define PD_OPT_SHA2      1<<31  // "sha2",       "generate sha2 of file"

typedef struct _options_t {
  int opt;
  char *s;
  char *d;
} options_t;

options_t opts[] =
{ { PD_OPT_ALL,      "all",        "dump all"},
  { PD_OPT_ARCH,     "arch",       "dump architecture directory"},
  { PD_OPT_BOUND,    "bound",      "dump bound import directory"},
  { PD_OPT_SECURITY, "security",   "dump security directory"},
  { PD_OPT_DEBUG,    "debug",      "dump debug directory"},
  { PD_OPT_DISASM,   "disasm",     "disassemble executable sections (x86/x64 only)"},
  { PD_OPT_DOS_HDR,  "dos",        "dump dos header"},
  { PD_OPT_EXPORTS,  "exports",    "dump export directory"},
  { PD_OPT_EXTRACT,  "extract",    "extract sections and resources to file"},
  { PD_OPT_FILE_HDR, "file",       "dump file header"},
  { PD_OPT_GBL,      "gbl",        "global pointer (MIPS)"},
  { PD_OPT_ALL_HDR,  "headers",    "dos, file, optional and section headers"},
  { PD_OPT_HEX,      "hex",        "display hexadecimal values for data and resources"},
  { PD_OPT_IMPORTS,  "imports",    "dump import directory"},
  { PD_OPT_LOAD_CFG, "loadconfig", "dump load configuration"},
  { PD_OPT_OPT_HDR,  "optional",   "dump optional header of PE"},
  { PD_OPT_RESOURCE, "resource",   "dump resource directory"},
  { PD_OPT_SECTION,  "section",    "dump sections"},
  { PD_OPT_SFC,      "sfc",        "is file protected by SFC"},
  { PD_OPT_MD5,      "md5",        "generate MD5 of file"},
  { PD_OPT_SHA1,     "sha1",       "generate SHA-1 of file"},
  { PD_OPT_SHA2,     "sha2",       "generate SHA-256 of file"},
  { PD_OPT_STRINGS,  "strings",    "dump strings"},
  { PD_OPT_TLS,      "tls",        "TLS directory"},
  { PD_OPT_VERSION,  "version",    "dump version information"},
  { PD_OPT_VERIFY,   "verify",     "verify if signed"},
  //{ PD_OPT_VIRUS,    "virus",      "queries VirusTotal.com for file report"},
};

static void ShowStrings(void *const info, const DWORD lang)
{
#define ARRAY_LEN(Array)  (sizeof(Array) / sizeof(Array[0]))
  char *stringnames[] =
  {"Comments",
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "LegalTrademarks",
    "OriginalFilename",
    "PrivateBuild",
    "ProductName",
    "ProductVersion",
    "SpecialBuild"
  };

  int i;

  for (i = 0; i < ARRAY_LEN(stringnames); i++)
  {
    char query[500];
    LPSTR value;
    UINT len;

    sprintf(query, "\\StringFileInfo\\%04x%04x\\%s", LOWORD(lang), HIWORD(lang), stringnames[i]);
    if (!VerQueryValue(info, query, (LPVOID*)&value, &len) || !len)
    continue;
    CharToOem(value, value);
    printf("  %-16s: %s\n", stringnames[i], value);
  }

#undef ARRAY_LEN
}


void vinfo (char *progname)
{
  DWORD dummy, infosize;

  if (!(infosize = GetFileVersionInfoSize(progname, &dummy)))
  {
    puts("(no version info)");
    return;
  }
  else
  {
    void *info = malloc(infosize);
    VS_FIXEDFILEINFO *fixed_info;
    UINT fixed_len;

    if (!info)
    {
      puts("(error on malloc");
      return;
    }

    GetFileVersionInfo(progname, 0, infosize, info);
    VerQueryValue(info, "\\", (LPVOID*)&fixed_info, (PUINT)&fixed_len);

    /* File Version */
    printf("File Version:    %d.%d.%d.%d\n",
    HIWORD(fixed_info->dwFileVersionMS),
    LOWORD(fixed_info->dwFileVersionMS),
    HIWORD(fixed_info->dwFileVersionLS),
    LOWORD(fixed_info->dwFileVersionLS));

    /* Product Version */
    printf("Product Version: %d.%d.%d.%d\n",
    HIWORD(fixed_info->dwProductVersionMS),
    LOWORD(fixed_info->dwProductVersionMS),
    HIWORD(fixed_info->dwProductVersionLS),
    LOWORD(fixed_info->dwProductVersionLS));

    {                     /* File Flags */
      DWORD flags = fixed_info->dwFileFlags & fixed_info->dwFileFlagsMask;
      fputs("Flags:           ", stdout);
      if (!flags)
      fputs("(none)", stdout);
      if (flags & VS_FF_DEBUG)
      fputs("Debug ", stdout);
      if (flags & VS_FF_PRERELEASE)
      fputs("Prerelease ", stdout);
      if (flags & VS_FF_PATCHED)
      fputs("Patched ", stdout);
      if (flags & VS_FF_PRIVATEBUILD)
      fputs("PrivateBuild ", stdout);
      if (flags & VS_FF_INFOINFERRED)
      fputs("InfoInferred ", stdout);
      if (flags & VS_FF_SPECIALBUILD)
      fputs("SpecialBuild ", stdout);
      putchar('\n');
    }

    {                     /* File OS. */
      fputs("OS:              ", stdout);
      switch (LOWORD(fixed_info->dwFileOS))
      {
      case VOS__WINDOWS16:
        fputs("16-Bit Windows", stdout);
        break;
      case VOS__PM16:
        fputs("16-Bit Presentation Manager", stdout);
        break;
      case VOS__PM32:
        fputs("32-Bit Presentation Manager", stdout);
        break;
      case VOS__WINDOWS32:
        fputs("Win32", stdout);
        break;
      default:
        fputs("(unknown)", stdout);
        break;
      }
      fputs(" on ", stdout);
      switch (MAKELONG(0, HIWORD(fixed_info->dwFileOS)))
      {
      case VOS_DOS:
        puts("MS-DOS");
        break;
      case VOS_OS216:
        puts("16-Bit OS/2");
        break;
      case VOS_OS232:
        puts("32-Bit OS/2");
        break;
      case VOS_NT:
        puts("NT");
        break;
      default:
        puts("(unknown)");
        break;
      }
    }

    /* file type */
    fputs("Type:            ", stdout);
    switch (fixed_info->dwFileType)
    {
    case VFT_APP:
      puts("Exe");
      break;
    case VFT_DLL:
      puts("DLL");
      break;
    case VFT_DRV:
      switch (fixed_info->dwFileSubtype)
      {
      case VFT2_DRV_COMM:
        puts("driver (serial)");
        break;
      case VFT2_DRV_PRINTER:
        puts("driver (printer)");
        break;
      case VFT2_DRV_KEYBOARD:
        puts("driver (keyboard)");
        break;
      case VFT2_DRV_LANGUAGE:
        puts("driver (language)");
        break;
      case VFT2_DRV_DISPLAY:
        puts("driver (screen)");
        break;
      case VFT2_DRV_MOUSE:
        puts("driver (mouse)");
        break;
      case VFT2_DRV_NETWORK:
        puts("driver (network)");
        break;
      case VFT2_DRV_SYSTEM:
        puts("driver (system)");
        break;
      case VFT2_DRV_INSTALLABLE:
        puts("driver (installable)");
        break;
      case VFT2_DRV_SOUND:
        puts("driver (sound)");
        break;
      case VFT2_UNKNOWN:
      default:
        puts("driver (unknown)");
        break;
      }

      break;
    case VFT_FONT:
      switch (fixed_info->dwFileSubtype)
      {
      case VFT2_FONT_RASTER:
        puts("font (raster)");
        break;
      case VFT2_FONT_VECTOR:
        puts("font (vector)");
        break;
      case VFT2_FONT_TRUETYPE:
        puts("font (truetype)");
        break;
      case VFT2_UNKNOWN:
      default:
        puts("font (unknown)");
        break;
      }

      break;

    case VFT_VXD:
      printf("virtual device (VxD), device id == %ld\n", fixed_info->dwFileSubtype);
      break;
    case VFT_STATIC_LIB:
      puts("static Lib");
      break;
    case VFT_UNKNOWN:
    default:
      puts("(unknown)");
      break;
    }


    /* languages and strings */
    {
      LPDWORD langs;
      UINT len, i;
      char buffer[MAX_PATH];

      VerQueryValue(info, "\\VarFileInfo\\Translation", (LPVOID*)&langs, &len);

      for (i = 0; i < len; i += sizeof(*langs), langs++)
      {               /* Get the string name for the language number. */
        VerLanguageName(LOWORD(*langs), buffer, sizeof(buffer));
        fputs("- ", stdout);
        puts(buffer);
        ShowStrings(info, *langs);
      }
    }

    free(info);

  }
}

BOOL vesig (LPCWSTR pwszSourceFile)
{
  LONG lStatus;
  DWORD dwLastError;

  // Initialize the WINTRUST_FILE_INFO structure.

  WINTRUST_FILE_INFO FileData;
  memset(&FileData, 0, sizeof(FileData));
  FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
  FileData.pcwszFilePath = pwszSourceFile;
  FileData.hFile = NULL;
  FileData.pgKnownSubject = NULL;

  /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:
    
    1) The certificate used to sign the file chains up to a root 
    certificate located in the trusted root certificate store. This 
    implies that the identity of the publisher has been verified by 
    a certification authority.
    
    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the  
    end entity certificate is stored in the trusted publisher store,  
    implying that the user trusts content from this publisher.
    
    3) The end entity certificate has sufficient permission to sign 
    code, as indicated by the presence of a code signing EKU or no 
    EKU.
    */

  GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA WinTrustData;

  // Initialize the WinVerifyTrust input data structure.

  // Default all fields to 0.
  memset(&WinTrustData, 0, sizeof(WinTrustData));

  WinTrustData.cbStruct = sizeof(WinTrustData);
  
  // Use default code signing EKU.
  WinTrustData.pPolicyCallbackData = NULL;

  // No data to pass to SIP.
  WinTrustData.pSIPClientData = NULL;

  // Disable WVT UI.
  WinTrustData.dwUIChoice = WTD_UI_NONE;

  // No revocation checking.
  WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 

  // Verify an embedded signature on a file.
  WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

  // Verify action.
  WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

  // Verification sets this value.
  WinTrustData.hWVTStateData = NULL;

  // Not used.
  WinTrustData.pwszURLReference = NULL;

  // This is not applicable if there is no UI because it changes 
  // the UI to accommodate running applications instead of 
  // installing applications.
  WinTrustData.dwUIContext = 0;

  // Set pFile.
  WinTrustData.pFile = &FileData;

  // WinVerifyTrust verifies signatures as specified by the GUID 
  // and Wintrust_Data.
  lStatus = WinVerifyTrust(
  NULL,
  &WVTPolicyGUID,
  &WinTrustData);

  switch (lStatus) 
  {
  case ERROR_SUCCESS:
    /*
            Signed file:
                - Hash that represents the subject is trusted.

                - Trusted publisher without any verification errors.

                - UI was disabled in dwUIChoice. No publisher or 
                    time stamp chain errors.

                - UI was enabled in dwUIChoice and the user clicked 
                    "Yes" when asked to install and run the signed 
                    subject.
            */
    wprintf(L"\nThe file \"%s\" is signed and the signature "
    L"was verified.\n",
    pwszSourceFile);
    break;
    
  case TRUST_E_NOSIGNATURE:
    // The file was not signed or had a signature 
    // that was not valid.

    // Get the reason for no signature.
    dwLastError = GetLastError();
    if (TRUST_E_NOSIGNATURE == dwLastError ||
        TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
        TRUST_E_PROVIDER_UNKNOWN == dwLastError) 
    {
      // The file was not signed.
      wprintf(L"\nThe file \"%s\" is not signed.\n",
      pwszSourceFile);
    } 
    else 
    {
      // The signature was not valid or there was an error 
      // opening the file.
      wprintf(L"\nAn unknown error occurred trying to "
      L"verify the signature of the \"%s\" file.\n",
      pwszSourceFile);
    }

    break;

  case TRUST_E_EXPLICIT_DISTRUST:
    // The hash that represents the subject or the publisher 
    // is not allowed by the admin or user.
    wprintf(L"The signature is present, but specifically "
    L"disallowed.\n");
    break;

  case TRUST_E_SUBJECT_NOT_TRUSTED:
    // The user clicked "No" when asked to install and run.
    wprintf(L"The signature is present, but not "
    L"trusted.\n");
    break;

  case CRYPT_E_SECURITY_SETTINGS:
    /*
            The hash that represents the subject or the publisher 
            was not explicitly trusted by the admin and the 
            admin policy has disabled user trust. No signature, 
            publisher or time stamp errors.
            */
    wprintf(L"CRYPT_E_SECURITY_SETTINGS - The hash "
    L"representing the subject or the publisher wasn't "
    L"explicitly trusted by the admin and admin policy "
    L"has disabled user trust. No signature, publisher "
    L"or timestamp errors.\n");
    break;

  default:
    // The UI was disabled in dwUIChoice or the admin policy 
    // has disabled user trust. lStatus contains the 
    // publisher or time stamp chain error.
    wprintf(L"Error is: 0x%x.\n",
    lStatus);
    break;
  }

  // Any hWVTStateData must be released by a call with close.
  WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

  lStatus = WinVerifyTrust(
  NULL,
  &WVTPolicyGUID,
  &WinTrustData);

  return true;
}


// return pointer to DOS header
PIMAGE_DOS_HEADER DosHdr (void)
{
  return (PIMAGE_DOS_HEADER)lpAddress;
}

// return pointer to NT header
PIMAGE_NT_HEADERS NtHdr (void)
{
  return (PIMAGE_NT_HEADERS) (lpAddress + DosHdr()->e_lfanew);
}

// return pointer to File header
PIMAGE_FILE_HEADER FileHdr (void)
{
  return &NtHdr()->FileHeader;
}

// determines CPU architecture of binary
BOOL is32 (void)
{
  return FileHdr()->Machine==IMAGE_FILE_MACHINE_I386;
}

// determines CPU architecture of binary
BOOL is64 (void)
{
  return FileHdr()->Machine==IMAGE_FILE_MACHINE_AMD64;
}

// return pointer to Optional header
LPVOID OptHdr (void)
{
  return (LPVOID)&NtHdr()->OptionalHeader;
}

// return pointer to first section header
PIMAGE_SECTION_HEADER SecHdr (void)
{
  PIMAGE_NT_HEADERS nt=NtHdr();
  
  return (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
  nt->FileHeader.SizeOfOptionalHeader);
}

DWORD DirSize (void)
{
  if (is32()) {
    return ((PIMAGE_OPTIONAL_HEADER32)OptHdr())->NumberOfRvaAndSizes;
  } else {
    return ((PIMAGE_OPTIONAL_HEADER64)OptHdr())->NumberOfRvaAndSizes;
  }
}

DWORD SecSize (void)
{
  return NtHdr()->FileHeader.NumberOfSections;
}

PIMAGE_DATA_DIRECTORY Dirs (void)
{
  if (is32()) {
    return ((PIMAGE_OPTIONAL_HEADER32)OptHdr())->DataDirectory;
  } else {
    return ((PIMAGE_OPTIONAL_HEADER64)OptHdr())->DataDirectory;
  }
}

ULONGLONG ImgBase (void)
{
  if (is32()) {
    return ((PIMAGE_OPTIONAL_HEADER32)OptHdr())->ImageBase;
  } else {
    return ((PIMAGE_OPTIONAL_HEADER64)OptHdr())->ImageBase;
  }
}

// valid dos header?
int valid_dos_hdr (void)
{
  PIMAGE_DOS_HEADER dos=DosHdr();
  if (dos->e_magic!=IMAGE_DOS_SIGNATURE) return 0;
  return (dos->e_lfanew != 0);
}

// valid nt headers
int valid_nt_hdr (void)
{
  return NtHdr()->Signature==IMAGE_NT_SIGNATURE;
}

int isObj (void) {
  PIMAGE_DOS_HEADER dos=DosHdr();
  
  return ((dos->e_magic==IMAGE_FILE_MACHINE_AMD64 ||
  dos->e_magic==IMAGE_FILE_MACHINE_I386) && 
  dos->e_sp==0);
}

DWORD rva2ofs (DWORD rva) {
  int i;
  
  PIMAGE_SECTION_HEADER sec=SecHdr();
  
  for (i=0; i<SecSize(); i++) {
    if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
    return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
  }
  return -1;
}

typedef struct _HDR_CHAR {
  DWORD dwFlag;
  char *s;
} HDR_CHAR;

HDR_CHAR machine_flags[] =
{ { IMAGE_FILE_MACHINE_I386,  "x86" },
  { IMAGE_FILE_MACHINE_IA64,  "Intel Itanium" },
  { IMAGE_FILE_MACHINE_AMD64, "x64" }
};

HDR_CHAR hdr_flags[] =
{ { IMAGE_FILE_RELOCS_STRIPPED,         "Relocs stripped" },
  { IMAGE_FILE_EXECUTABLE_IMAGE,        "Executable" },
  { IMAGE_FILE_LINE_NUMS_STRIPPED,      "COFF lines stripped" },
  { IMAGE_FILE_LOCAL_SYMS_STRIPPED,     "COFF symbols stripped" },
  { IMAGE_FILE_AGGRESIVE_WS_TRIM,       "Aggressive Trim" },
  { IMAGE_FILE_LARGE_ADDRESS_AWARE,     "Application can handle large (>2GB) addresses" },
  { IMAGE_FILE_BYTES_REVERSED_LO,       "Lo Bytes reversed" },
  { IMAGE_FILE_32BIT_MACHINE,           "32 bit word machine" },
  { IMAGE_FILE_DEBUG_STRIPPED,          "Debug stripped" },
  { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "If removable run from swap" },
  { IMAGE_FILE_NET_RUN_FROM_SWAP,       "If network run from swap" },
  { IMAGE_FILE_SYSTEM,                  "System" },
  { IMAGE_FILE_DLL,                     "DLL" },
  { IMAGE_FILE_UP_SYSTEM_ONLY,          "Uniprocessor only" },
  { IMAGE_FILE_BYTES_REVERSED_HI,       "Hi Bytes reversed" } 
};

HDR_CHAR magic_flags[] =
{ { IMAGE_NT_OPTIONAL_HDR32_MAGIC,      "PE32" },
  { IMAGE_NT_OPTIONAL_HDR64_MAGIC,      "PE32+"},
  { IMAGE_ROM_OPTIONAL_HDR_MAGIC,       "ROM"  }
};

HDR_CHAR dll_flags[] =
{ { IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,          "Dynamic Base" },
  { IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,       "Force Integrity" },
  { IMAGE_DLLCHARACTERISTICS_NX_COMPAT,             "NX compatible" },
  { IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,          "No isolation" },
  { IMAGE_DLLCHARACTERISTICS_NO_SEH,                "No SEH" },
  { IMAGE_DLLCHARACTERISTICS_NO_BIND,               "No bind" },
  { IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,            "WDM Driver" },
  { IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "Terminal Server Aware" }
};

HDR_CHAR sub_flags[] =
{ { IMAGE_SUBSYSTEM_UNKNOWN,                  "Unknown"},
  { IMAGE_SUBSYSTEM_NATIVE,                   "Native"},
  { IMAGE_SUBSYSTEM_WINDOWS_GUI,              "Windows GUI"},
  { IMAGE_SUBSYSTEM_WINDOWS_CUI,              "Windows CUI"},
  { IMAGE_SUBSYSTEM_OS2_CUI,                  "OS2 CUI"},
  { IMAGE_SUBSYSTEM_POSIX_CUI,                "POSIX CUI"},
  { IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,           "Windows CE GUI"},
  { IMAGE_SUBSYSTEM_EFI_APPLICATION,          "EFI Application"},
  { IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,  "EFI Boot Service Driver"},
  { IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,       "EFI Runtime Driver"},
  { IMAGE_SUBSYSTEM_EFI_ROM,                  "EFI ROM"},
  { IMAGE_SUBSYSTEM_XBOX,                     "XBOX"},
  { IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, "Windows Boot Application"}
};

HDR_CHAR section_flags[] =
{ { IMAGE_SCN_CNT_CODE,               "Code"},
  { IMAGE_SCN_CNT_INITIALIZED_DATA,   "Initialized Data"},
  { IMAGE_SCN_CNT_UNINITIALIZED_DATA, "Uninitialized Data"},
  { IMAGE_SCN_MEM_NOT_CACHED,         "Not cached"},
  { IMAGE_SCN_MEM_NOT_PAGED,          "Not paged"},
  { IMAGE_SCN_MEM_SHARED,             "Shared"},
  { IMAGE_SCN_MEM_EXECUTE,            "Execute"},
  { IMAGE_SCN_MEM_READ,               "Read"},
  { IMAGE_SCN_MEM_WRITE,              "Write"},
};

HDR_CHAR cert_flags[] =
{ { WIN_CERT_TYPE_X509,             "X509"},
  { WIN_CERT_TYPE_PKCS_SIGNED_DATA, "PKCS Signed Data" },
  { WIN_CERT_TYPE_RESERVED_1,       "Reserved" },
  { WIN_CERT_TYPE_TS_STACK_SIGNED,  "TS Stack Signed" },
  { WIN_CERT_TYPE_EFI_PKCS115,      "PKCS 115" },
  { WIN_CERT_TYPE_EFI_GUID,         "PKCS" }
};

HDR_CHAR debug_flags[] =
{ { IMAGE_DEBUG_TYPE_UNKNOWN,   "UNKNOWN"},
  { IMAGE_DEBUG_TYPE_COFF,      "COFF"},
  { IMAGE_DEBUG_TYPE_CODEVIEW,  "CODEVIEW"},
  { IMAGE_DEBUG_TYPE_FPO,       "FPO"},
  { IMAGE_DEBUG_TYPE_MISC,      "MISC"},
  { IMAGE_DEBUG_TYPE_EXCEPTION, "EXCEPTION"},
  { IMAGE_DEBUG_TYPE_FIXUP,     "FIXUP"},
  { IMAGE_DEBUG_TYPE_BORLAND,   "BORLAND"}
};

HDR_CHAR rsrc_types[] =
{ { (DWORD)-1,               "Unknown"       },
  { (DWORD)RT_CURSOR,        "Cursor"        },
  { (DWORD)RT_BITMAP,        "Bitmap"        },
  { (DWORD)RT_ICON,          "Icon"          },
  { (DWORD)RT_MENU,          "Menu"          },
  { (DWORD)RT_DIALOG,        "Dialog"        },
  { (DWORD)RT_STRING,        "String"        },
  { (DWORD)RT_FONTDIR,       "Font Dir"      },
  { (DWORD)RT_ACCELERATOR,   "Accelerator"   },
  { (DWORD)RT_RCDATA,        "Font"          },
  { (DWORD)RT_MESSAGETABLE,  "Font"          },
  { (DWORD)RT_GROUP_CURSOR,  "Group Cursor"  },
  { (DWORD)RT_GROUP_ICON,    "Group Icon"    },
  { (DWORD)RT_VERSION,       "Version"       },
  { (DWORD)RT_DLGINCLUDE,    "Dialog Include"},
  { (DWORD)RT_PLUGPLAY,      "Plug n Play"   },
  { (DWORD)RT_VXD,           "VXD"           },
  { (DWORD)RT_ANICURSOR,     "Ani Cursor"    },
  { (DWORD)RT_ANIICON,       "Ani Icon"      },
  { (DWORD)RT_HTML,          "HTML"          },
  { (DWORD)RT_MANIFEST,      "Manifest"      }
};

void flags2str (DWORD flags, HDR_CHAR *hdrs, int len)
{
  int i, j;
  
  for (i=0; i<len/sizeof (HDR_CHAR); i++) {
    if (flags & hdrs[i].dwFlag) {
      for (j=0; j<=8; j++) putchar(' ');
      printf ("%s\n", hdrs[i].s);
    }
  }
}

char *flag2str (DWORD flag, HDR_CHAR *hdrs, int len)
{
  int i;

  for (i=0; i<len/sizeof (HDR_CHAR); i++) {
    if (flag==hdrs[i].dwFlag) {
      return hdrs[i].s;
    }
  }
  return hdrs[0].s;
}

char *time2str (time_t *t)
{
  static char s[128];
  struct tm *ti;
  
  ti=localtime (t);
  return asctime (ti);
}

char *word2str (char fmt[], ...)
{
  va_list arglist;
  static char buffer[2048];
  
  va_start (arglist, fmt);
  vsprintf (buffer, fmt, arglist);
  va_end (arglist);
  
  return buffer;
}

void bin2file (BYTE bin[], DWORD len)
{
  FILE *out=fopen ("cert.bin", "wb");
  if (out!=NULL)
  {
    fwrite (bin, 1, len, out);
    fclose (out);
  }
}

void bin2hex (BYTE bin[], DWORD len)
{
  DWORD str_len=0;
  BYTE *str;
  
  if (CryptBinaryToString (bin, len, CRYPT_STRING_HEXASCIIADDR, NULL, &str_len))
  {
    str=(BYTE*)HeapAlloc (GetProcessHeap(), 0, str_len);
    if (str!=NULL) 
    {
      if (CryptBinaryToString (bin, len, CRYPT_STRING_HEXASCIIADDR, (LPSTR)str, &str_len))
      {
        printf ("%s", str);
      }
      HeapFree (GetProcessHeap(), 0, str);
    }
  }
}

#include "udis86.h"

// return the max length of instruction in input
int ud_insn_max (BYTE* input, DWORD inlen)
{
  int insn_max=0, len;
  ud_t ud_obj;
  
  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, is32() ? 32 : 64);
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);
  ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);
  //ud_set_input_file (&ud_obj, input);
  ud_set_input_buffer(&ud_obj, input, inlen);
  
  while (ud_disassemble(&ud_obj)) {
    len=ud_insn_len(&ud_obj);
    insn_max=(len>insn_max) ? len : insn_max;
  }
  //fseek (input, 0, SEEK_SET);
  return insn_max;
}

// return the max length of assembly string in input
int ud_asm_max (BYTE* input, DWORD inlen)
{
  int asm_max=0, len;
  ud_t ud_obj;
  
  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, is32() ? 32 : 64);
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);
  ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);
  //ud_set_input_file (&ud_obj, input);
  ud_set_input_buffer(&ud_obj, input, inlen);
  
  while (ud_disassemble(&ud_obj)) {
    len=strlen(ud_insn_asm(&ud_obj));
    asm_max=(len>asm_max) ? len : asm_max;
  }
  //fseek (input, 0, SEEK_SET);
  return asm_max;
}

// display shellcode in C style string
void bin2sc (BYTE *input, DWORD inlen)
{
  ud_t ud_obj;
  uint32_t insn_max=ud_insn_max(input, inlen) * 4;
  uint32_t asm_max=ud_asm_max(input, inlen);
  int len, ofs, i;
  const char *ins;
  const uint8_t *hex;

  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, is32() ? 32 : 64);
  ud_set_pc (&ud_obj, 0);
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);
  ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);
  //ud_set_input_file (&ud_obj, input);
  ud_set_input_buffer(&ud_obj, input, inlen);
  
  while (ud_disassemble(&ud_obj)) {
    len=ud_insn_len(&ud_obj);
    ofs=ud_insn_off(&ud_obj);
    ins=ud_insn_asm(&ud_obj);
    hex=ud_insn_ptr(&ud_obj);
    
    // print the offset
    printf ("\n  /* %04X */ ", ofs);
    
    // print hex bytes
    putchar ('\"');
    for (i=0; i<len; i++) { 
      printf ("\\x%02x", hex[i]);
    }
    putchar ('\"');
    len*=4;
    
    // pad remainder with spaces
    while (len++ < insn_max) putchar (' ');
    
    // print asm string
    printf (" /* %-*s */", asm_max, ins);
  }
  printf("\n};");
}

void bin2dis (BYTE *input, DWORD inlen)
{
  ud_t ud_obj;
  const ud_operand *opr;
  uint32_t insn_max=ud_insn_max(input, inlen) * 3;
  uint32_t asm_max=ud_asm_max(input, inlen);
  uint64_t len, ofs, i;
  const char *ins;
  const uint8_t *hex;

  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, is32() ? 32 : 64);
  ud_set_pc (&ud_obj, ImgBase());
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);
  ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);
  //ud_set_input_file (&ud_obj, input);
  ud_set_input_buffer(&ud_obj, input, inlen);
  
  while (ud_disassemble(&ud_obj)) {
    len=ud_insn_len(&ud_obj);
    ofs=ud_insn_off(&ud_obj);
    ins=ud_insn_asm(&ud_obj);
    hex=ud_insn_ptr(&ud_obj);
    
    //opr=ud_insn_opr (&ud_obj, 0);
    
    /*if (opr!=NULL) printf ("\n%08X", opr->base);
    if (opr!=NULL) printf ("\n%08X", opr->index);
    if (opr!=NULL) printf ("\n%08X", opr->scale);
    if (opr!=NULL) printf ("\n%08X", opr->offset);
    if (opr!=NULL) printf ("\n%08X", opr->lval);
    */
    // print the offset
    if (is32()) {
      printf ("\n%08X", ofs);
    } else {
      printf ("\n%016llX", ofs);
    }
    // print hex bytes
    for (i=0; i<len; i++) { 
      printf (" %02x", hex[i]);
    }
    len*=3;
    
    // pad remainder with spaces
    while (len++ < insn_max) putchar (' ');
    
    // print asm string
    printf (" %-*s", asm_max, ins);
  }
}

void sec_headers (void)
{
  DWORD i, ofs;
  PIMAGE_SECTION_HEADER sec=SecHdr();
  PBYTE pRawData;
  
  for (i=0; i<SecSize(); i++) 
  {
    printf ("\nSECTION HEADER #%i\n", i+1);
    printf ("%8s name\n",            sec[i].Name);
    printf ("%8X virtual size\n",    sec[i].Misc.VirtualSize);
    
    if (is32())
    {
      printf ("%8X virtual address (%08X to %08X)\n",
      sec[i].VirtualAddress, 
      (DWORD)img_base + sec[i].VirtualAddress, 
      (DWORD)img_base + sec[i].Misc.VirtualSize - 1);      
    } else {
      printf ("%8X virtual address (%016llX to %016llX)\n",
      sec[i].VirtualAddress, 
      img_base + sec[i].VirtualAddress, 
      img_base + sec[i].Misc.VirtualSize);
    }
    printf ("%8X size of raw data (%i bytes padding)\n",
    sec[i].SizeOfRawData, 
    sec[i].SizeOfRawData - sec[i].Misc.VirtualSize - 1);
    
    printf ("%8X file pointer to raw data (%08X to %08X)\n", 
    sec[i].PointerToRawData, sec[i].PointerToRawData, 
    sec[i].PointerToRawData + sec[i].SizeOfRawData - 1);
    
    printf ("%8X file pointer to relocation table\n",   sec[i].PointerToRelocations);
    printf ("%8X file pointer to line numbers\n",       sec[i].PointerToLinenumbers);
    printf ("%8X number of relocations\n",              sec[i].NumberOfRelocations);
    printf ("%8X number of line numbers\n",             sec[i].NumberOfLinenumbers);
    printf ("%8X flags\n",                              sec[i].Characteristics);
    
    flags2str (sec[i].Characteristics, (HDR_CHAR*)section_flags, sizeof (section_flags));
    
    ofs=rva2ofs (sec[i].VirtualAddress);
    if (ofs != -1)
    {
      pRawData = (PBYTE) (lpAddress + ofs);
      if (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) {
        if (flags & PD_OPT_DISASM) {
          bin2dis (pRawData, sec[i].SizeOfRawData);
        }
      } else if (sec[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        if (flags & PD_OPT_HEX) {
          bin2hex (pRawData, sec[i].SizeOfRawData);
        }
      }
    }
  }
}

void dump_imp_desc (IMAGE_IMPORT_DESCRIPTOR *imp)
{
  IMAGE_THUNK_DATA32      *iat32, *f32;
  IMAGE_THUNK_DATA64      *iat64, *f64;
  IMAGE_IMPORT_BY_NAME    *ibn;
  DWORD                   ofs, i, j;
  
  for (i=0; ; i++) {
    if (imp[i].Name==0) break;
    ofs=rva2ofs(imp[i].Name);
    if (ofs!=-1) 
    {
      printf ("\nName:%s", ofs + lpAddress);
      if (imp[i].OriginalFirstThunk!=0) {
        ofs=rva2ofs(imp[i].OriginalFirstThunk);  
      } else {
        ofs=rva2ofs(imp[i].FirstThunk);
      }
      if (ofs!=-1) 
      {
        if (is64()) {
          iat64=(IMAGE_THUNK_DATA64*)(ofs + lpAddress);
          ofs=rva2ofs(imp[i].FirstThunk);
          f64=(IMAGE_THUNK_DATA64*)(ofs + lpAddress);
        } else {
          iat32=(IMAGE_THUNK_DATA32*)(ofs + lpAddress);
          ofs=rva2ofs(imp[i].FirstThunk);
          f32=(IMAGE_THUNK_DATA32*)(ofs + lpAddress);
        }
        
        for (j=0; ; j++) 
        {
          if (is64()) {
            if (iat64[j].u1.AddressOfData == 0) 
            break;
            ofs=rva2ofs(iat64[j].u1.AddressOfData);
            if (ofs!=-1) {
              ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
              printf ("\n\t%016llX\t%s", f64[j].u1.Function, ibn->Name);
            }
          } else {
            if (iat32[j].u1.AddressOfData == 0) 
            break;   
            ofs=rva2ofs(iat32[j].u1.AddressOfData);
            if (ofs!=-1) {
              ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
              printf ("\n\t%08X\t%s", f32[j].u1.Function , ibn->Name);
            }
          }
        }
      }
    }
  }
}

void exp_dir (IMAGE_DATA_DIRECTORY *dir)
{
  DWORD                  cnt=0, ofs=0, idx;
  IMAGE_EXPORT_DIRECTORY *exp;
  DWORD                  *adr;
  DWORD                  *sym;
  WORD                   *ord;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress!=0) 
  {
    ofs=rva2ofs(dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (ofs != -1) 
    {
      exp=(IMAGE_EXPORT_DIRECTORY*) (ofs + lpAddress);
      
      cnt=exp->NumberOfNames;
      adr=(DWORD*) (rva2ofs(exp->AddressOfFunctions)    + lpAddress);
      sym=(DWORD*) (rva2ofs(exp->AddressOfNames)        + lpAddress);
      ord=(WORD*)  (rva2ofs(exp->AddressOfNameOrdinals) + lpAddress);
      ofs=(DWORD)  (rva2ofs(exp->Name)                  + lpAddress);
      
      printf ("  [ Characteristics          : %08X\n", exp->Characteristics);
      printf ("  [ Time Date Stamp          : %08X\n", exp->TimeDateStamp);
      printf ("  [ Major Version            : %04X\n", exp->MajorVersion);
      printf ("  [ Minor Version            : %04X\n", exp->MinorVersion); 
      printf ("  [ Number of Functions      : %08X\n", exp->NumberOfFunctions);
      printf ("  [ Number of Names          : %08X\n", exp->NumberOfNames);
      printf ("  [ Address of functions     : %08X\n", exp->AddressOfFunctions);
      printf ("  [ Address of names         : %08X\n", exp->AddressOfNames);
      printf ("  [ Address of Name Ordinals : %08X\n", exp->AddressOfNameOrdinals);
      printf ("  [ Name                     : %08X\n", exp->Name);
      
      if (ofs!=-1) {
        printf ("\nName : %s", (BYTE*)ofs);
        
        for (idx=0; idx<cnt; idx++) {
          
          ofs=rva2ofs ((DWORD)sym[idx]);
          if (ofs!=-1) {
            printf ("\n  %04X %08X %s (%016llX)", 
            ord[idx], adr[ord[idx]], 
            ofs + lpAddress, adr[ord[idx]] + img_base);
          }
        }
      }
    }
  }
  printf ("\nNumber of functions   : %i",      cnt);
  printf ("\nNumber of directories : %i",      DirSize());
  printf ("\nBase of image         : %016llX", ImgBase());
}

void imp_dir (IMAGE_DATA_DIRECTORY *dir)
{
  DWORD cnt=0, ofs=0, i, j;
  IMAGE_IMPORT_DESCRIPTOR *imp;
  IMAGE_THUNK_DATA32      *iat32, *f32;
  IMAGE_THUNK_DATA64      *iat64, *f64;
  IMAGE_IMPORT_BY_NAME    *ibn;

  if (dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress!=0) {
    ofs=rva2ofs(dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (ofs!=-1) {
      imp=(IMAGE_IMPORT_DESCRIPTOR *) (lpAddress + ofs);
      for (i=0; ; i++) {
        if (imp[i].Name==0) break;
        ofs=rva2ofs(imp[i].Name);
        if (ofs!=-1) 
        {
          printf ("\n%s", ofs + lpAddress);
          if (imp[i].OriginalFirstThunk!=0) {
            ofs=rva2ofs(imp[i].OriginalFirstThunk);  
          } else {
            ofs=rva2ofs(imp[i].FirstThunk);
          }
          if (ofs!=-1) 
          {
            if (is64()) {
              iat64=(IMAGE_THUNK_DATA64*)(ofs + lpAddress);
              ofs=rva2ofs(imp[i].FirstThunk);
              f64=(IMAGE_THUNK_DATA64*)(ofs + lpAddress);
            } else {
              iat32=(IMAGE_THUNK_DATA32*)(ofs + lpAddress);
              ofs=rva2ofs(imp[i].FirstThunk);
              f32=(IMAGE_THUNK_DATA32*)(ofs + lpAddress);
            }
            
            for (j=0; ; j++) 
            {
              if (is64()) {
                if (iat64[j].u1.AddressOfData == 0) 
                break;
                ofs=rva2ofs(iat64[j].u1.AddressOfData);
                if (ofs!=-1) {
                  ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
                  printf ("\n\t%016llX\t%s", f64[j].u1.Function, ibn->Name);
                }
              } else {
                if (iat32[j].u1.AddressOfData == 0) 
                break;   
                ofs=rva2ofs(iat32[j].u1.AddressOfData);
                if (ofs!=-1) {
                  ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
                  printf ("\n\t%08X\t%s", f32[j].u1.Function , ibn->Name);
                }
              }
            }
          }
        }
      }
    }
  }
  printf ("\nNumber of functions   : %i", cnt);
  printf ("\nNumber of directories : %i", DirSize());
  printf ("\nBase of image         : %016llX", ImgBase());
}
void parse_dir (PIMAGE_RESOURCE_DIRECTORY ird, DWORD ofs, int idx);

void parse_data (PIMAGE_RESOURCE_DIRECTORY resdir, DWORD ofs, int idx)
{
  PIMAGE_RESOURCE_DATA_ENTRY irde;
  DWORD data_ofs;
  
  irde=(PIMAGE_RESOURCE_DATA_ENTRY) ((BYTE*)resdir + ofs);
  data_ofs=rva2ofs (irde->OffsetToData);
  
  if (flags & PD_OPT_HEX) 
  bin2hex ((BYTE*)lpAddress + data_ofs, irde->Size);
  
  if (flags & PD_OPT_EXTRACT)
  bin2file ((BYTE*)lpAddress + data_ofs, irde->Size);
}

void parse_dir_entry (PIMAGE_RESOURCE_DIRECTORY resdir, PIMAGE_RESOURCE_DIRECTORY_ENTRY irde, int idx)
{
  PIMAGE_RESOURCE_DIRECTORY    t;
  PIMAGE_RESOURCE_DIR_STRING_U s;

  if (irde->NameIsString) {
    s=(PIMAGE_RESOURCE_DIR_STRING_U) ((BYTE*)resdir + irde->NameOffset);
    printf ("%*ws name\n", idx+16, s->NameString);
  } else {
    printf ("%*i id\n", idx+16, irde->Id);
  }
  // if directory, process
  if (irde->DataIsDirectory) {
    parse_dir (resdir, irde->OffsetToDirectory, idx+4);
  } else {
    parse_data (resdir, irde->OffsetToData, idx+4);
  } 
}

void parse_dir (PIMAGE_RESOURCE_DIRECTORY resdir, DWORD ofs, int idx)
{
  PIMAGE_RESOURCE_DIR_STRING_U    irds;
  PIMAGE_RESOURCE_DIRECTORY_ENTRY irde;
  PIMAGE_RESOURCE_DIRECTORY       ird;
  
  ird=(PIMAGE_RESOURCE_DIRECTORY) ((BYTE*) resdir + ofs);
  
  int total = ird->NumberOfNamedEntries + ird->NumberOfIdEntries;
  irde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (ird + 1);
  
  for (int i=0; i<total; i++) {
    parse_dir_entry (resdir, irde, idx);
    irde++;
  }
}

void res_dir (IMAGE_DATA_DIRECTORY *dir)
{
  PIMAGE_RESOURCE_DIRECTORY       ird;
  PIMAGE_RESOURCE_DIRECTORY_ENTRY irde;
  PIMAGE_RESOURCE_DATA_ENTRY      irdata;
  PIMAGE_RESOURCE_DIR_STRING_U    irds;
  int total;
  DWORD ofs;
  WCHAR name[32];
  
  if (dir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress==0) return;
  
  ofs=rva2ofs(dir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
  if (ofs == -1) return;
  ird = (PIMAGE_RESOURCE_DIRECTORY) (ofs + lpAddress); 
  
  printf ("\nRESOURCE DIRECTORY VALUES\n");
  printf ("%16X characteristics\n", ird->Characteristics);
  printf ("%16X time date stamp %s", 
  ird->TimeDateStamp, time2str((time_t*)&ird->TimeDateStamp));
  printf ("%16s version\n", 
  word2str ("%i.%02i", ird->MajorVersion, ird->MinorVersion));
  printf ("%16X number of named entries\n", ird->NumberOfNamedEntries);
  printf ("%16X number of id entries\n",    ird->NumberOfIdEntries);

  // for some reason, my msvc has DirectoryEntries commented out of structure
  //irde = (IMAGE_RESOURCE_DIRECTORY_ENTRY)ird->DirectoryEntries;
  //irde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (ird + 1);
  parse_dir (ird, 0, 4);
}

void xcept_dir (IMAGE_DATA_DIRECTORY *dir)
{
  IMAGE_RUNTIME_FUNCTION_ENTRY *rfe;
  DWORD ofs;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress!=0) {
    ofs=rva2ofs (dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    if (ofs!=-1)
    {
      rfe=(IMAGE_RUNTIME_FUNCTION_ENTRY*) (lpAddress + ofs);
      printf ("\nEXCEPTION DIRECTORY VALUES\n");
      printf ("%16X Begin Address\n", rfe->BeginAddress);
      printf ("%16X End Address\n", rfe->EndAddress);
      printf ("%16X Unwind Address\n", rfe->UnwindInfoAddress);
    }
  }
}

// openssl pkcs7 -inform DER -print_certs -text -in cert.bin
void sec_dir (IMAGE_DATA_DIRECTORY *dir)
{
  WIN_CERTIFICATE *wc;
  int           ofs, size;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress!=0) {
    ofs=dir[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    size=dir[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    printf ("\nCERTIFICATE DIRECTORY VALUES\n");
    while (size > 0) {
      wc = (WIN_CERTIFICATE*) (lpAddress + ofs);
      printf ("\nLength   : %i\n", wc->dwLength);
      printf ("Revision : %i\n",   wc->wRevision);
      printf ("Type     : %04X\n", wc->wCertificateType);
      flags2str (wc->wCertificateType, (HDR_CHAR*)cert_flags, sizeof (cert_flags));
      
      if (flags & PD_OPT_HEX) 
      bin2hex (wc->bCertificate, wc->dwLength);
      
      if (flags & PD_OPT_EXTRACT) 
      bin2file (wc->bCertificate, wc->dwLength);
      
      size -= (wc->dwLength + (8 - (wc->dwLength % 8)));
      ofs  += (wc->dwLength + (8 - (wc->dwLength % 8)));
    }
  }
}

void base_dir (IMAGE_DATA_DIRECTORY *dir)
{
  if (dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress!=0) {
    printf ("\nHas base relocation directory");
  }
}

void debug_dir (IMAGE_DATA_DIRECTORY *dir)
{
  DWORD ofs;
  IMAGE_DEBUG_DIRECTORY *idd;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress!=0) {
    ofs=rva2ofs (dir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    idd=(IMAGE_DEBUG_DIRECTORY*)(lpAddress + ofs);
    printf ("\nDEBUG DIRECTORY VALUES\n");
    printf ("%16X characteristics\n", idd->Characteristics);
    printf ("%16X time date stamp %s", idd->TimeDateStamp, time2str((time_t*)&idd->TimeDateStamp));
    printf ("%16s version\n", word2str ("%i.%02i", idd->MajorVersion, idd->MinorVersion));
    printf ("%16X type\n", idd->Type);
    flags2str (idd->Type, debug_flags, sizeof (debug_flags));
    printf ("%16X size of data\n", idd->SizeOfData);
    printf ("%16X address Of raw data\n", idd->AddressOfRawData);
    printf ("%16X pointer to raw data\n", idd->PointerToRawData);
  }
}

void arch_dir (IMAGE_DATA_DIRECTORY *dir)
{
  if (dir[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress!=0) {
    printf ("\nHas arch directory");
  }
}

void gbl_dir (IMAGE_DATA_DIRECTORY *dir)
{
  if (dir[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress!=0) {
    printf ("\nHas global pointer directory");
  }
}

void tls_dir (IMAGE_DATA_DIRECTORY *dir)
{
  IMAGE_TLS_DIRECTORY32 *tls32;
  IMAGE_TLS_DIRECTORY64 *tls64;
  DWORD ofs;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress!=0) {
    ofs=rva2ofs (dir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    if (ofs!=-1) {
      printf ("\nTLS DIRECTORY VALUES\n");
      if (is64()) 
      {
        tls64=(IMAGE_TLS_DIRECTORY64*) (lpAddress + ofs);
        
        printf ("%20.016llX start address of raw data\n", tls64->StartAddressOfRawData);
        printf ("%20.016llX end address of raw data\n",   tls64->EndAddressOfRawData);
        printf ("%20.016llX address of index\n",          tls64->AddressOfIndex);
        printf ("%20.016llX address of callbacks\n",      tls64->AddressOfCallBacks);
        printf ("%20X size of zero fill\n\n",             tls64->SizeOfZeroFill);
      } else {
        tls32=(IMAGE_TLS_DIRECTORY32*) (lpAddress + ofs);
        
        printf ("%20.08X start address of raw data\n",   tls32->StartAddressOfRawData);
        printf ("%20.08X end address of raw data\n",     tls32->EndAddressOfRawData);
        printf ("%20.08X address of index\n",            tls32->AddressOfIndex);
        printf ("%20.08X address of callbacks\n",        tls32->AddressOfCallBacks);
        printf ("%20X size of zero fill\n\n",            tls32->SizeOfZeroFill);
      }
    }
  }
}

void load_cfg_dir (IMAGE_DATA_DIRECTORY *dir)
{
  DWORD                         ofs, cnt, *ptr, tbl;
  ULONGLONG                     *ptr64;
  PIMAGE_LOAD_CONFIG_DIRECTORY32 lcd32;
  PIMAGE_LOAD_CONFIG_DIRECTORY64 lcd64;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress!=0) {
    ofs = rva2ofs(dir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    if (ofs != -1)
    {
      printf ("\n  Section contains the following load config:\n");
      if (is64()) {
        lcd64=(PIMAGE_LOAD_CONFIG_DIRECTORY64) (lpAddress + ofs);
        
        printf ("%16X size\n",                             lcd64->Size);
        printf ("%16X time date stamp\n",                  lcd64->TimeDateStamp);
        printf ("%16s Version\n", word2str ("%i.%02i",     lcd64->MajorVersion, lcd64->MinorVersion));
        printf ("%16X GlobalFlags Clear\n",                lcd64->GlobalFlagsClear);
        printf ("%16X GlobalFlags Set\n",                  lcd64->GlobalFlagsSet);
        printf ("%16X Critical Section Default Timeout\n", lcd64->CriticalSectionDefaultTimeout);
        printf ("%16llX Decommit Free Block Threshold\n",  lcd64->DeCommitFreeBlockThreshold);
        printf ("%16llX Decommit Total Free Threshold\n",  lcd64->DeCommitTotalFreeThreshold);
        printf ("%16llX Lock Prefix Table\n",              lcd64->LockPrefixTable);
        printf ("%16llX Maximum Allocation Size\n",        lcd64->MaximumAllocationSize);
        printf ("%16llX Virtual Memory Threshold\n",       lcd64->VirtualMemoryThreshold);
        printf ("%16llX Process Heap Flags\n",             lcd64->ProcessAffinityMask);
        printf ("%16X Process Affinity Mask\n",            lcd64->ProcessHeapFlags);
        printf ("%16X CSD Version\n",                      lcd64->CSDVersion);
        printf ("%16X Reserved\n",                         lcd64->Reserved1);
        printf ("%16llX Edit list\n",                      lcd64->EditList);
        printf ("%16llX Security Cookie\n",                lcd64->SecurityCookie);
        printf ("%16llX Safe Exception Handler Table\n",   lcd64->SEHandlerTable);
        printf ("%16llX Safe Exception Handler Count\n",   lcd64->SEHandlerCount);
        
        tbl=(lcd64->SEHandlerTable - (DWORD)ImgBase());
        ofs=rva2ofs (tbl);
        
        if (ofs != -1) 
        {
          ptr64=(ULONGLONG*) (ofs + lpAddress);
          for (cnt=0; cnt<lcd64->SEHandlerCount; cnt++) {
            printf ("%16llX\n", ptr64[cnt] + ImgBase());
          }
        }
      } else {
        lcd32=(PIMAGE_LOAD_CONFIG_DIRECTORY32) (lpAddress + ofs);
        
        printf ("%16X size\n",                             lcd32->Size);
        printf ("%16X time date stamp\n",                  lcd32->TimeDateStamp);
        printf ("%16s Version\n", word2str ("%i.%02i",     lcd32->MajorVersion, lcd32->MinorVersion));
        printf ("%16X GlobalFlags Clear\n",                lcd32->GlobalFlagsClear);
        printf ("%16X GlobalFlags Set\n",                  lcd32->GlobalFlagsSet);
        printf ("%16X Critical Section Default Timeout\n", lcd32->CriticalSectionDefaultTimeout);
        printf ("%16X Decommit Free Block Threshold\n",    lcd32->DeCommitFreeBlockThreshold);
        printf ("%16X Decommit Total Free Threshold\n",    lcd32->DeCommitTotalFreeThreshold);
        printf ("%16X Lock Prefix Table\n",                lcd32->LockPrefixTable);
        printf ("%16lX Maximum Allocation Size\n",         lcd32->MaximumAllocationSize);
        printf ("%16X Virtual Memory Threshold\n",         lcd32->VirtualMemoryThreshold);
        printf ("%16X Process Heap Flags\n",               lcd32->ProcessAffinityMask);
        printf ("%16X Process Affinity Mask\n",            lcd32->ProcessHeapFlags);
        printf ("%16X CSD Version\n",                      lcd32->CSDVersion);
        printf ("%16X Reserved\n",                         lcd32->Reserved1);
        printf ("%16X Edit list\n",                        lcd32->EditList);
        printf ("%16X Security Cookie\n",                  lcd32->SecurityCookie);
        printf ("%16X Safe Exception Handler Table\n",     lcd32->SEHandlerTable);
        printf ("%16X Safe Exception Handler Count\n",     lcd32->SEHandlerCount);
        
        tbl=(lcd32->SEHandlerTable - (DWORD)ImgBase());
        ofs=rva2ofs (tbl);
        
        if (ofs != -1) 
        {
          ptr=(DWORD*) (ofs + lpAddress);
          for (cnt=0; cnt<lcd32->SEHandlerCount; cnt++) {
            printf ("%16X\n", ptr[cnt] + ImgBase());
          }
        }
      }
    }
  }
}

void bound_dir (IMAGE_DATA_DIRECTORY *dir)
{
  PIMAGE_BOUND_IMPORT_DESCRIPTOR bid;
  DWORD ofs;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress!=0) {
    printf (" - has it");
    ofs=rva2ofs (dir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
    if (ofs != -1)
    {
      bid=(PIMAGE_BOUND_IMPORT_DESCRIPTOR) (lpAddress + ofs);
      printf ("%16X time date stamp (%s)\n", time2str ((time_t*)&bid->TimeDateStamp));
    }
  }
}

void iat_dir (IMAGE_DATA_DIRECTORY *dir)
{
  if (dir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress!=0) {
    printf ("\nHas IAT directory");
  }
}

typedef struct _ImgDelayDescr_t {
  DWORD grAttrs;
  DWORD rvaDLLName;
  DWORD rvaHmod;
  DWORD rvaIAT;
  DWORD rvaINT;
  DWORD rvaBoundIAT;
  DWORD rvaUnloadIAT;
  DWORD dwTimeStamp;
} ImgDelayDescr;

void delay_dir (IMAGE_DATA_DIRECTORY *dir)
{
  ImgDelayDescr *idd;
  IMAGE_THUNK_DATA *nt;
  IMAGE_THUNK_DATA32 *iat32, *f32;
  IMAGE_THUNK_DATA64 *iat64, *f64;
  IMAGE_THUNK_DATA *biat;
  IMAGE_THUNK_DATA *uiat;
  IMAGE_IMPORT_BY_NAME *ibn;
  LPCSTR           dll;
  DWORD ofs, i, j;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress!=0) {
    /*
    ofs=rva2ofs(dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    if (ofs!=-1) {
      idd=(ImgDelayDescr*) (lpAddress + ofs);
      for (; idd->rvaHmod; idd++) {
        dll  = (LPCSTR)(rva2ofs(idd->rvaDLLName)              + lpAddress);
        printf ("\n%s", dll);
        
        if (is64()) 
        {
          nt    = (IMAGE_THUNK_DATA*)(rva2ofs(idd->rvaINT)       + lpAddress);
          iat64 = (IMAGE_THUNK_DATA64*)(rva2ofs(idd->rvaIAT)     + lpAddress);
          biat  = (IMAGE_THUNK_DATA*)(rva2ofs(idd->rvaBoundIAT)  + lpAddress);
          uiat  = (IMAGE_THUNK_DATA*)(rva2ofs(idd->rvaUnloadIAT) + lpAddress);
        } else {
          nt    = (IMAGE_THUNK_DATA*)(rva2ofs(idd->rvaINT)       + lpAddress);
          iat32 = (IMAGE_THUNK_DATA32*)(rva2ofs(idd->rvaIAT)     + lpAddress);
          biat  = (IMAGE_THUNK_DATA*)(rva2ofs(idd->rvaBoundIAT)  + lpAddress);
          uiat  = (IMAGE_THUNK_DATA*)(rva2ofs(idd->rvaUnloadIAT) + lpAddress);          
        }
        
        for (j=0; ; j++) 
        {
          if (is64()) 
          {
            if (iat64[j].u1.AddressOfData == 0) 
              break;
            ofs=rva2ofs(iat64[j].u1.AddressOfData);
            if (ofs!=-1) {
              ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
              //printf ("\n\t%016llX\t%s", f64[j].u1.Function, ibn->Name);
            }
          } else {
            if (iat32[j].u1.AddressOfData == 0) 
              break;   
            ofs=rva2ofs(iat32[j].u1.AddressOfData);
            if (ofs!=-1) {
              ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
              //printf ("\n\t%08X\t%s", f32[j].u1.Function , ibn->Name);
            }
          }
          printf ("\n%s", ibn->Name);
        }
        printf ("\n%s", time2str((time_t*)&idd->dwTimeStamp));
        
      }
    }*/
  }
}

void com_dir (IMAGE_DATA_DIRECTORY *dir)
{
  if (dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress!=0) {
    printf ("\nHas COM descriptor directory");
  }
}
// dump the file header
void file_header (void)
{
  PIMAGE_FILE_HEADER hdr=FileHdr();
  int i, j;
  
  printf ("\n\nFILE HEADER VALUES\n");
  printf ("%16X machine (%s)\n",                 hdr->Machine, 
  flag2str(hdr->Machine, machine_flags, sizeof (machine_flags)) );
  printf ("%16X number of sections\n",           hdr->NumberOfSections);
  printf ("%16X time date stamp %s",           hdr->TimeDateStamp, 
  time2str ((time_t*)&hdr->TimeDateStamp));
  printf ("%16X file pointer to symbol table\n", hdr->PointerToSymbolTable);
  printf ("%16X number of symbols\n",            hdr->NumberOfSymbols);
  printf ("%16X size of optional header\n",      hdr->SizeOfOptionalHeader);
  printf ("%16X characteristics\n",              hdr->Characteristics);
  
  flags2str(hdr->Characteristics, hdr_flags, sizeof(hdr_flags));
}

void dos_hdr (void)
{
  PIMAGE_DOS_HEADER idh;
  
  idh=DosHdr();
  
  printf ("\n\nDOS HEADER VALUES\n");
  printf ("%16X EXE Signature\n", idh->e_magic);
  printf ("%16X Size of Last Page\n", idh->e_cblp);
  printf ("%16X Number of 512 byte pages in file\n", idh->e_cp);
  printf ("%16X Number of Relocation Entries\n", idh->e_crlc);
  printf ("%16X Header size in Paragraphs\n", idh->e_cparhdr);
  printf ("%16X Minimum additional Memory required in paragraphs\n", idh->e_minalloc);
  printf ("%16X Maximum additional Memory required in paragraphs\n", idh->e_maxalloc);
  printf ("%16X Initial SS relative to start of file\n", idh->e_ss);
  printf ("%16X Initial SP\n", idh->e_sp);
  printf ("%16X Checksum (unused)\n", idh->e_csum);
  printf ("%16X Initial IP\n", idh->e_ip);
  printf ("%16X Initial CS relative to start of file\n", idh->e_cs);
  printf ("%16X Offset within Header of Relocation Table\n", idh->e_lfarlc);
  printf ("%16X Overlay Number\n", idh->e_ovno);
  printf ("%16X OEM Id\n", idh->e_oemid);
  printf ("%16X OEM Info\n", idh->e_oeminfo);
  printf ("%16X Offset to PE header\n", idh->e_lfanew);
}

// dump the optional header for 64-bit
void opt_header (void)
{
  PIMAGE_OPTIONAL_HEADER32 hdr32;
  PIMAGE_OPTIONAL_HEADER64 hdr64;

  if (is32())
  {
    hdr32=(PIMAGE_OPTIONAL_HEADER32)OptHdr();
    
    printf ("\n\nOPTIONAL HEADER VALUES\n");
    printf ("%16X magic # (%s)\n", hdr32->Magic,
    flag2str (hdr32->Magic, magic_flags, sizeof (magic_flags)));
    printf ("%16s linker version\n", 
    word2str ("%i.%02i", hdr32->MajorLinkerVersion, hdr32->MinorLinkerVersion));
    printf ("%16X size of code\n", hdr32->SizeOfCode);
    printf ("%16X size of initialized data\n", hdr32->SizeOfInitializedData);
    printf ("%16X size of uninitialized data\n", hdr32->SizeOfUninitializedData);
    printf ("%16X entry point (%08X)\n", 
    hdr32->AddressOfEntryPoint, hdr32->ImageBase + hdr32->AddressOfEntryPoint);
    printf ("%16X base of code\n", hdr32->BaseOfCode);
    printf ("%16X base of data\n", hdr32->BaseOfData);
    printf ("%16X image base (%08X to %08X)\n", 
    hdr32->ImageBase, hdr32->ImageBase, hdr32->ImageBase + hdr32->SizeOfImage - 1);
    printf ("%16X section alignment\n", hdr32->SectionAlignment);
    printf ("%16X file alignment\n", hdr32->FileAlignment);
    printf ("%16s operating system version\n",
    word2str ("%i.%02i", hdr32->MajorOperatingSystemVersion, 
    hdr32->MinorOperatingSystemVersion));
    printf ("%16s image version\n",
    word2str ("%i.%02i", hdr32->MajorImageVersion, hdr32->MinorImageVersion));
    printf ("%16s subsystem version\n", 
    word2str ("%i.%02i", hdr32->MajorSubsystemVersion, hdr32->MinorSubsystemVersion));
    printf ("%16X Win32 version\n",         hdr32->Win32VersionValue);
    printf ("%16X size of image\n",         hdr32->SizeOfImage);
    printf ("%16X size of headers\n",       hdr32->SizeOfHeaders);
    printf ("%16X checksum\n",              hdr32->CheckSum);
    printf ("%16X subsystem (%s)\n",        hdr32->Subsystem, 
    flag2str(hdr32->Subsystem, (HDR_CHAR*)sub_flags, sizeof(sub_flags)));
    printf ("%16X DLL characteristics\n",   hdr32->DllCharacteristics);
    
    flags2str(hdr32->DllCharacteristics, (HDR_CHAR*)dll_flags, sizeof(dll_flags));

    printf ("%16X size of stack reserve\n", hdr32->SizeOfStackReserve);
    printf ("%16X size of stack commit\n",  hdr32->SizeOfStackCommit);
    printf ("%16X size of heap reserve\n",  hdr32->SizeOfHeapReserve);
    printf ("%16X size of heap commit\n",   hdr32->SizeOfHeapCommit);
    printf ("%16X loader flags\n",          hdr32->LoaderFlags);
    printf ("%16X number of directories\n", hdr32->NumberOfRvaAndSizes);
  } 
  else
  {  
    hdr64=(PIMAGE_OPTIONAL_HEADER64)OptHdr();
    
    printf ("\nOPTIONAL HEADER VALUES\n");
    printf ("%16X magic # (%s)\n", hdr64->Magic,
    flag2str (hdr64->Magic, magic_flags, sizeof (magic_flags)));
    printf ("%16s linker version\n", 
    word2str ("%i.%02i", hdr64->MajorLinkerVersion, hdr64->MinorLinkerVersion));
    printf ("%16X size of code\n", hdr64->SizeOfCode);
    printf ("%16X size of initialized data\n", hdr64->SizeOfInitializedData);
    printf ("%16X size of uninitialized data\n", hdr64->SizeOfUninitializedData);
    printf ("%16X entry point (%016llX)\n", 
    hdr64->AddressOfEntryPoint, hdr64->ImageBase + hdr64->AddressOfEntryPoint);
    printf ("%16X base of code\n", hdr64->BaseOfCode);
    //printf ("%16X base of data\n", hdr64->BaseOfData);
    printf ("%16llX image base (%016llX to %016llX)\n", 
    hdr64->ImageBase, hdr64->ImageBase, hdr64->ImageBase + hdr64->SizeOfImage - 1);
    printf ("%16X section alignment\n", hdr64->SectionAlignment);
    printf ("%16X file alignment\n", hdr64->FileAlignment);
    printf ("%16s operating system version\n",
    word2str ("%i.%02i", hdr64->MajorOperatingSystemVersion, hdr64->MinorOperatingSystemVersion));
    printf ("%16s image version\n",
    word2str ("%i.%02i", hdr64->MajorImageVersion, hdr64->MinorImageVersion));
    printf ("%16s subsystem version\n", 
    word2str ("%i.%02i", hdr64->MajorSubsystemVersion, hdr64->MinorSubsystemVersion));
    printf ("%16X Win32 version\n",         hdr64->Win32VersionValue);
    printf ("%16X size of image\n",         hdr64->SizeOfImage);
    printf ("%16X size of headers\n",       hdr64->SizeOfHeaders);
    printf ("%16X checksum\n",              hdr64->CheckSum);
    printf ("%16X subsystem (%s)\n",        hdr64->Subsystem, 
    flag2str(hdr64->Subsystem, (HDR_CHAR*)sub_flags, sizeof(sub_flags)));
    printf ("%16X DLL characteristics\n",   hdr64->DllCharacteristics);
    
    flags2str(hdr64->DllCharacteristics, (HDR_CHAR*)dll_flags, sizeof(dll_flags));
    
    printf ("%16X size of stack reserve\n", hdr64->SizeOfStackReserve);
    printf ("%16X size of stack commit\n",  hdr64->SizeOfStackCommit);
    printf ("%16X size of heap reserve\n",  hdr64->SizeOfHeapReserve);
    printf ("%16X size of heap commit\n",   hdr64->SizeOfHeapCommit);
    printf ("%16X loader flags\n",          hdr64->LoaderFlags);
    printf ("%16X number of directories\n", hdr64->NumberOfRvaAndSizes);
  }
}

void parse_dirs (void)
{
  PIMAGE_DATA_DIRECTORY dir=Dirs();
  
  if (flags & PD_OPT_EXPORTS)  exp_dir (dir);
  if (flags & PD_OPT_IMPORTS)  imp_dir (dir);
  if (flags & PD_OPT_RESOURCE) res_dir (dir);
  if (flags & PD_OPT_EXCEPT)   xcept_dir (dir);
  if (flags & PD_OPT_SECURITY) sec_dir (dir);
  if (flags & PD_OPT_RELOC)    base_dir (dir);
  if (flags & PD_OPT_DEBUG)    debug_dir (dir);
  if (flags & PD_OPT_ARCH)     arch_dir (dir);
  if (flags & PD_OPT_GBL)      gbl_dir (dir);
  if (flags & PD_OPT_TLS)      tls_dir (dir);
  if (flags & PD_OPT_LOAD_CFG) load_cfg_dir (dir);
  if (flags & PD_OPT_BOUND)    bound_dir (dir);
  if (flags & PD_OPT_IAT)      iat_dir (dir);
  if (flags & PD_OPT_DELAY)    delay_dir (dir);
  if (flags & PD_OPT_COM)      com_dir (dir);
}

void dump_img (void)
{ 
  if (!valid_dos_hdr()) {
    printf ("  [ invalid dos header\n");
    return;
  }
  
  // MZ header
  if (flags & PD_OPT_DOS_HDR) {
    dos_hdr ();
  }
  
  if (!valid_nt_hdr()) {
    printf ("  [ invalid nt header\n");
    return;
  }
  
  // PE file header
  if (flags & PD_OPT_FILE_HDR) {
    file_header ();
  }
  
  // PE optional header
  if (flags & PD_OPT_OPT_HDR) {
    opt_header ();
  }
  
  // PE sections
  if (flags & PD_OPT_SECTION) {
    sec_headers ();
  }
  
  // directories
  parse_dirs ();
}

int open_img (char f[])
{ 
  int     r=0;
  wchar_t wcs[MAX_PATH];
  
  /*fd=fopen (f, "rb");
  if (fd!=NULL) {
    stat (f, &st);
    lpAddress=malloc (st.st_size);
    if (lpAddress!=NULL) {
      fread (lpAddress
      r=1;
    }
  }*/
  
  hFile=CreateFile (f, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile!=INVALID_HANDLE_VALUE) {
    hMap=CreateFileMapping (hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap!=NULL) {
      lpAddress=(LPBYTE)MapViewOfFile (hMap, FILE_MAP_READ, 0, 0, 0);
      r=1;
      mbstowcs (wcs, f, MAX_PATH);
      
      // check if protected file
      if (flags & PD_OPT_SFC) {
        printf ("\nSFC protected : %s\n", SfcIsFileProtected (NULL, wcs) ? "Yes" : "No");
      }
      
      // verify embedded signature
      if (flags & PD_OPT_VERIFY) {
        vesig (wcs);
      }
      
      // dump version information
      if (flags & PD_OPT_VERSION)
      vinfo (f);
    }
  }
  return r;
}

void close_img (void)
{
  if (lpAddress!=NULL) UnmapViewOfFile ((LPCVOID)lpAddress);
  if (hMap     !=NULL) CloseHandle (hMap);
  if (hFile    !=NULL) CloseHandle (hFile);
}

char* getparam (int argc, char *argv[], int *i)
{
  int n=*i;
  if (argv[n][2] != 0) {
    return &argv[n][2];
  }
  if ((n+1) < argc) {
    *i=n+1;
    return argv[n+1];
  }
  printf ("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
  exit (0);
}

void usage (void)
{
  int i, len;
  
  printf ("\n  usage: pedump [options] <file(s)> (wildcard accepted)\n");
  for (i=0; i<sizeof (opts) / sizeof (options_t); i++) {
    printf ("    /%s", opts[i].s);
    len=strlen(opts[i].s);
    len = (-len + 20);
    while (--len) putchar (' ');
    printf ("%s\n", opts[i].d);
  }
  exit (0);
}

int main (int argc, char *argv[])
{
  char opt, ok;
  int i, j, test=0, wc=0;
  PVOID OldValue=NULL;
  char *shdr=NULL, *xtract=NULL, *cpu=NULL;

  Wow64DisableWow64FsRedirection (&OldValue);
  
  // for each argument
  for (i=1; i<argc; i++)
  {
    // is this option?
    if (argv[i][0]=='/')
    {
      ok=0;
      for (j=0; j<sizeof (opts)/sizeof (options_t); j++) {
        if (strcmp (&argv[i][1], opts[j].s)==0) {
          flags |= opts[j].opt; ok=1;
          break;
        }
      }
      if (!ok) usage();
    } else
    if (wc==0) {
      wc=i;
    }
  }
  
  if (wc==0) usage();
  
  for (i=wc; argv[i]!=NULL; i++) {
    if (argv[i][0] != '/') 
    {
      printf ("\nChecking %s", argv[i]);
      if (open_img(argv[i])) {
        if (isObj()) {
          printf ("\nLooks like an object file");
        } else {
          dump_img ();
        }
      }
      close_img();
    }
  }
  return 0;
}
