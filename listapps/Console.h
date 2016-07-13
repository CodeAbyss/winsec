
#ifndef CONSOLE_H
#define CONSOLE_H

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <string>

#define print wprintf

class Console {

  public:
    static VOID setBufWidth(SHORT X);
    static VOID setBufHeight(SHORT Y);

    static DWORD getBufWidth();
    static DWORD getBufHeight();
        
    static VOID cursor(BOOL bVisible);
    
    static VOID setx(DWORD X);
    static VOID sety(DWORD Y);
    
    static DWORD getx();
    static DWORD gety();
    
    static VOID setxy(DWORD X, DWORD Y);
    static VOID setTitle(std::wstring title);
    static wchar_t getchar();
    static void clear();
};

#endif