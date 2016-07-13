
#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <string>

/**
 *
 * translate error code to string
 *
 */
const wchar_t* GetError(DWORD errCode, std::wstring &result)
{
  wchar_t* msg;

  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                errCode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&msg,
                0,
                NULL);
  result = msg;
  LocalFree(msg);
  return result.c_str();
}
