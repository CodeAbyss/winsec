

                  PE Dumper
            
[ intro

This is a simple PE dumper for Windows 32/64-bit executables in progress which
means it isn't ready for release but I store almost everything on github in case my computer
dies..


C:\github\pedump\bin\x64>pedump pedump.exe

Checking pedump.exe

FILE HEADER VALUES
            8664 machine (x64)
               5 number of sections
        55526D66 time date stamp Tue May 12 22:15:18 2015
               0 file pointer to symbol table
               0 number of symbols
              F0 size of optional header
              22 characteristics
                     Executable
                     Application can handle large (>2GB) addresses

OPTIONAL HEADER VALUES
             20B magic # (PE32+)
           10.00 linker version
            C800 size of code
            9200 size of initialized data
               0 size of uninitialized data
            3140 entry point (0000000140003140)
            1000 base of code
       140000000 image base (0000000140000000 to 0000000140018FFF)
            1000 section alignment
             200 file alignment
            5.02 operating system version
            0.00 image version
            5.02 subsystem version
               0 Win32 version
           19000 size of image
             400 size of headers
               0 checksum
               3 subsystem (Windows CUI)
            8140 DLL characteristics
                     Dynamic Base
                     NX compatible
                     Terminal Server Aware
          100000 size of stack reserve
            1000 size of stack commit
          100000 size of heap reserve
            1000 size of heap commit
               0 loader flags
              10 number of directories
              
              
TODO:
  * disassembler
  * extraction tool
  * dump exports
  * dump imports
  * coff parsing
  * linux