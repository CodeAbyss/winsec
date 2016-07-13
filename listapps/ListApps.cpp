
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _CRT_SECURE_NO_DEPRECATE

#include "console.h"

void startup()
{
  print(L"\nlistapps v0.1");
  print(L"\nCopyright (C) 2010  \n");
}

void usage()
{
  startup();
  print(L"\nUsage: listapps                          - local.\n");
  print(L"       listapps [computer]               - remote.\n");
  print(L"       listapps [computer a] [computer b] - show apps on [a] missing from [b]\n\n");
}
  
void list(std::wstring a);
void compare(std::wstring a, std::wstring b);
  
int wmain(int argc, wchar_t *argv[])
{ 
  Console::setTitle(L"listapps v0.1");
  
  switch(argc)
  {
    case 1:
      list(L"");
      break;
    case 2:
    {
      std::wstring arg = argv[1];
      if(arg == L"/?" || arg == L"-h" || arg == L"-?" || arg == L"--help") {
        usage();
      } else {
        list(argv[1]);
      }
      break;
    }
    case 3:
      compare(argv[1],argv[2]);
      break;
    default:
      usage();
      break;
  }
  
  return 0;
}

