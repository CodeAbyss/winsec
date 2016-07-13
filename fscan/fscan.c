/**
  Copyright (C) 2016 Odzhan.
  
  All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

typedef void (*cb_func) (char path[], WIN32_FIND_DATA *wfd);

typedef struct _fs_t {
    DWORD files;
    DWORD dirs;
} fs_t;

fs_t cnt={0,0};

void count_files (char path[], WIN32_FIND_DATA *wfd)
{
    if (wfd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
      cnt.dirs++;
    } else {
      cnt.files++;
    }
}

void print_files (char path[], WIN32_FIND_DATA *wfd)
{
    char fullpath[MAX_PATH*2];
    
    sprintf (fullpath, "%s\\%s", path, wfd->cFileName);
    
    if (wfd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
      printf ("\r%-260s", fullpath);
    } else {
      printf ("\n%-260s", fullpath);
    }
    count_files(NULL, wfd);
}

// scan fld for files matching fspec
void file_scan (char fld[], char fspec[], cb_func callback)
{
    WIN32_FIND_DATA wfd;
    HANDLE          hFind;
    char            path[1024];
    
    // scan for files matching specification
    sprintf (path, "%s\\%s", fld, fspec);
    
    hFind=FindFirstFile (path, &wfd);
    
    if (hFind!=INVALID_HANDLE_VALUE) {
      do {
        // not a directory?
        if (!(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
          // callback?
          if (callback!=NULL) {
            callback (fld, &wfd);
          }
        }
      } while (FindNextFile (hFind, &wfd));
      FindClose (hFind);
    }
}

// scan fld for folders matching fldspec
// for each one found, scan it for files matching fspec
void fld_scan (char fld[], char fldspec[], char fspec[], cb_func callback)
{
    WIN32_FIND_DATA wfd;
    HANDLE          hFind=NULL;
    char            path[1024];
    
    // find all folders
    sprintf (path, "%s\\*", fld);
    
    hFind=FindFirstFile (path, &wfd);
    
    if (hFind!=INVALID_HANDLE_VALUE) {
      do {
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          // don't process "." or ".."
          if ((strcmp (wfd.cFileName, "." )!=0) && 
              (strcmp (wfd.cFileName, "..")!=0))
          {
            sprintf (path, "%s\\%s", fld, wfd.cFileName);
            // does it match folder spec? if so, perform file scan
            if (PathMatchSpec(wfd.cFileName, fldspec)) {
              if (callback!=NULL) callback(fld, &wfd);
              // scan it for files matching fspec
              file_scan (path, fspec, callback);
            }
            // traverse folder
            fld_scan (path, fldspec, fspec, callback);
          }
        }
      } while (FindNextFile (hFind, &wfd));
      FindClose (hFind);
    }
}

void base_scan (char base[], char fldspec[], char fspec[])
{
  printf ("\nSearching %s\\%s for %s", base, fldspec, fspec);
  
  file_scan (base, fspec, print_files);
  fld_scan (base, fldspec, fspec, print_files);
}

// example of using fscan function
int main (int argc, char *argv[])
{
    char *base=NULL, *fldspec="*", *fspec="*";
    DWORD dwSize = MAX_PATH;
    char drives[MAX_PATH];

    if (argc<2) {
      printf ("  usage: fscan <base path> <folder spec> <file spec>\n");
      return 0;
    }
    
    base=argv[1];
    if (argc>=3) {
      fldspec=argv[2];
    }
    
    if (argc==4) {
      fspec=argv[3];
    }
    
    if (base[0]=='*') {
      // search all drives
      dwSize = GetLogicalDriveStrings(dwSize, drives);
      base = drives;
      while (*base) {
        //PathRemoveBackslash (base);
        base_scan (base, fldspec, fspec);
        base += strlen(base) + 1;
      }
    } else {
      base_scan(base, fldspec, fspec);
    }
    
    printf ("\n\nDirectories: %lu\nFiles: %lu\nTotal: %lu", 
      cnt.dirs, cnt.files, cnt.dirs + cnt.files);
    return 0;
}
