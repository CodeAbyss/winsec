

                            DPAPI Structure Analysis Tool
                            -----------------------------
                            
[ intro

CryptProtectData is part of DPAPI (Data Protection Application Programming Interface)
enabling programmers to access strong cryptography.

This utility explores the opaque data structures displaying values.

=======================================================================

[ usage

  dpapi_info v0.1 - DPAPI Structure Analysis Tool

    /b <file>  File containing DPAPI blob
    /c <file>  CREDHIST file
    /h         Dump hexadecimal values
    /p <file>  Preferred master key file
    /m <file>  Master key file
    /r         Scan registry for DPAPI blobs
    /s <file>  Scan file for DPAPI data
    /x         Extract DPAPI data to file

    
[ Credential History

XP : C:\Documents and Settings\<ntid>\Application Data\Microsoft\Protect
W7 : C:\Users\<ntid>\AppData\Roaming\Microsoft\Protect

Each time user resets password a CREDENTIAL_ENTRY is added to CREDHIST file located
in the users profile.
  
=======================================================================  
  * * * CREDHIST INFORMATION * * *

  Hash                 : SHA-512
  PBKDF Iterations     : 17400
  Cipher               : AES-256
  Salt                 : 9f7a1c3598ec3335ee64e13e709224a3
  Sid                  : 010500000000000515000000c1dd78d0f41a7e0f1ca9aae5e8030000
  SHA-1 Hash           : c45c8eef880620dc164cdabd2d2bc462fe08c10f
  NTLM Hash            : dab9105bd20548e8a89e9c111c30741498902601
  

=======================================================================

[ Preferred Master key

This indicates the file where a users master key resides.
Not displayed here is the 64-bit value at the end which is a FILETIME value
indicating last update.

  * * * PREFERRED MASTERKEY INFORMATION * * *

  GUID  : df9f7c62-34e2-4513-9683-3e61545a52d9
  
=======================================================================

[ Master key

XP : C:\WINDOWS\system32\Microsoft\Protect\S-1-5-18\User
W7 : C:\Windows\System32\Microsoft\Protect\S-1-5-18\User

The information stored in these files are required to encrypt/decrypt
DPAPI blobs.

  * * * MASTERKEY INFORMATION * * *

  Version              : 2
  GUID                 : df9f7c62-34e2-4513-9683-3e61545a52d9
  Policy               : 5
  User Key Size        : 176
  Local Enc Key Size   : 144
  Local Key Size       : 20
  Domain Key Size      : 0

  Version              : 2
  User Salt            : 30a2aeb14f98560d97863feea0714d45
  PBKDF                : 17400
  Hash                 : SHA-512
  Crypt                : AES-256
  User Key             : 725690948117a3c1879c5c58deb8b6097e3a90be4ea3faf74f8c5cc0e5c60bf516e6a...(truncated)

  Version              : 2
  User Salt            : 4bf8dac4f0a6ea5c24079867e003db5b
  PBKDF                : 17400
  Hash                 : SHA-512
  Crypt                : AES-256
  User Key             : 00c505c604c0b58f27e952befaeff363cc32cf0e157c61e617fe6ff758dd4d539b510...(truncated)
  
=======================================================================
[ DPAPI blobs

The opaque data structure returned by CryptProtectData is referred to as a DPAPI blob

  * * * DPAPI BLOB INFORMATION * * *

  Version              : 1
  Provider             : df9d8cd0-1501-11d1-8c7a-00c04fc297eb
  Version              : 1
  Master Key           : df9f7c62-34e2-4513-9683-3e61545a52d9
  Flags                : None
  Description          : (null)
  Cipher               : AES-256
  Salt                 : a08c8908218224c17a729ef58200064260a0dfba6a5406812a4a2d55228ff89d
  Key Alg              : SHA-512
  Key                  : ea2d9c0d2b35d9b4f3464b9e350fd319c67e082487ba41ecda9bd5304e3dbf0e
  Ciphertext           : 2a1deddf735fe37aa1c3371e29bdb3cd88b1a78529a134585c47c83419a60b059a759...(truncated)
  Hmac                 : 53081a30b41d1cc11d8eda700d478b96ca9b6580d22e9621efa4c7c2417833dc73619...(truncated)
  
  
  