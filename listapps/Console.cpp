
#include "console.h"

VOID Console::setTitle(std::wstring title) {
  SetConsoleTitle(title.c_str());
}

VOID Console::setBufWidth(SHORT X) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  if(X <= csbi.dwSize.X) return;
  csbi.dwSize.X  = X;
  SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE),csbi.dwSize);  
}

VOID Console::setBufHeight(SHORT Y) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  if(Y <= csbi.dwSize.Y) return;
  csbi.dwSize.Y  = Y;
  SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE),csbi.dwSize); 
}

DWORD Console::getBufWidth() {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  return csbi.dwSize.X; 
}

DWORD Console::getBufHeight() {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  return csbi.dwSize.Y; 
}

VOID Console::cursor(BOOL bVisible) {
  CONSOLE_CURSOR_INFO cci;
  GetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE),&cci);
  
  cci.bVisible = bVisible;
  SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE),&cci);
}

// horizontal
VOID Console::setx(DWORD X) {
  COORD pos;
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  pos.X = (SHORT)X;
  pos.Y = csbi.dwCursorPosition.Y;
  SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE),pos);
}

// vertical
VOID Console::sety(DWORD Y) {
  COORD pos;
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  pos.Y = (SHORT)Y;
  pos.X = csbi.dwCursorPosition.X;
  SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE),pos);
}

VOID Console::setxy(DWORD X, DWORD Y) {
  COORD pos;
  
  pos.X = (SHORT)X;
  pos.Y = (SHORT)Y;
  SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE),pos);
}

/**
 *
 * get a character on console from user
 *
 */
wchar_t Console::getchar()
{
  wchar_t c;

  DWORD saveMode;
  GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),&saveMode);
  SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),ENABLE_PROCESSED_INPUT);

  if(WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE),INFINITE) == WAIT_OBJECT_0) {
    DWORD num;
    ReadConsole(GetStdHandle(STD_INPUT_HANDLE),&c,1,&num,NULL);
  }

  SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),saveMode);
  return(c);
}

void Console::clear()
{
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  COORD start = {0,0};
  DWORD dwWritten;
  
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  FillConsoleOutputCharacter(GetStdHandle(STD_OUTPUT_HANDLE),32,csbi.dwSize.X * csbi.dwSize.Y,start,&dwWritten);
  setxy(0,0);
}

DWORD Console::gety()
{
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  return csbi.dwCursorPosition.Y;
}

DWORD Console::getx()
{
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
  
  return csbi.dwCursorPosition.X;
}