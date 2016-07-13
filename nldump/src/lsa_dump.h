


HWND hLsaWnd;
HTREEITEM hLsaTreeItem;

// display status of current window
TCHAR *lsa_status = TEXT("");

void initLSA()
{
  LOGFONT lf;
  HFONT hfNormal;

  hLsaWnd           = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,TEXT("RichEdit20W"),NULL,ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN | WS_VSCROLL | WS_CHILD,0,0,0,0,hMainWnd,NULL,hInst,NULL);
	tvis.item.lParam  = reinterpret_cast<LPARAM>(hLsaWnd);
	tvis.item.pszText = TEXT("LSA Secrets");
	hLsaTreeItem      = TreeView_InsertItem(hTreeWnd, &tvis);
  
  ZeroMemory(&lf,sizeof(LOGFONT));
  lstrcpy(lf.lfFaceName,TEXT("Courier"));
  
  lf.lfWeight = 12;
  lf.lfHeight = 12;

  hfNormal = CreateFontIndirect(&lf);
  SendMessage(hLsaWnd,WM_SETFONT,(WPARAM)hfNormal,MAKELPARAM(true,0));
}

// simple function to dump hexadecimal and printable values
// only intended for buffer sizes <= 256 
void dump_hex(const wchar_t str[], unsigned char pData[], size_t nDataSize)
{
  size_t slen = wcslen(str) + 32;
  wchar_t *buffer = new wchar_t[slen*2];
  UINT ndx;

  if (buffer != NULL)
  {
    ZeroMemory(buffer,slen*2);
    wsprintf(buffer,TEXT("\r\n%s\r\n"),str);

    ndx = GetWindowTextLength(hLsaWnd);

    #ifdef WIN32
      SendMessage (hLsaWnd, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
    #else
      SendMessage (hLsaWnd, EM_SETSEL, 0, MAKELONG (ndx, ndx));
    #endif
      SendMessage (hLsaWnd, EM_REPLACESEL, 0, (LPARAM) (LPSTR)buffer);
		
      SendMessage(hLsaWnd,WM_VSCROLL,SB_BOTTOM,(LPARAM)NULL );

    delete []buffer;
  }

  buffer = new wchar_t[nDataSize*2+2048];

  if (buffer != NULL)
  {
    ZeroMemory(buffer,nDataSize*2+2048);

    size_t i,j;
    wchar_t *ptr = buffer;

    for (i = 0;i < nDataSize;i += 16)
    {
      // display hexadecimal values
      for(j = 0;j < 16 && i+j < nDataSize;j++) {
        wsprintf(ptr,TEXT(" %02x"),pData[i+j]);
        ptr += 3;
      }

      while(j++ < 16) {
        lstrcat(buffer,TEXT("   "));
        ptr += 3;
      }

      lstrcat(buffer,TEXT("\t"));
      ptr++;

      // display printable values
      for (j = 0;j < 16 && i+j < nDataSize;j++) 
      {
        if (pData[i+j] == 0x09 || !iswprint(pData[i+j])) {
          lstrcat(buffer,TEXT("."));
          ptr++;
        }
        else {
          wsprintf(ptr++,TEXT("%c"),pData[i+j]);
        }
      }
      lstrcat(buffer,TEXT("\r\n"));
      ptr += 2;
    }
      ndx = GetWindowTextLength(hLsaWnd);

      #ifdef WIN32
        SendMessage (hLsaWnd, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
      #else
        SendMessage (hLsaWnd, EM_SETSEL, 0, MAKELONG (ndx, ndx));
      #endif
        SendMessage (hLsaWnd, EM_REPLACESEL, 0, (LPARAM) (LPSTR)buffer);
		
      SendMessage(hLsaWnd,WM_VSCROLL,SB_TOP,(LPARAM)NULL );

      delete []buffer;
  }
}

/**
 *
 * Dump LSA secrets
 *
 * Doesn't read keys which use null bytes "hidden keys"
 *
 */
void dump_lsa()
{
  LSA_LIST *slist = cdump->GetLsaEntries();

  if (slist == NULL)
  {
    lsa_status = TEXT("No LSA secrets found");
  }
  else
  {
    for(LSA_LIST *entries = slist;entries != NULL;entries = entries->next)
    {
      LSA_ENTRY *secret = entries->entry;

      dump_hex(secret->szKeyName,secret->LsaData.Buffer,secret->LsaData.dwSize);
    }
  }
}
