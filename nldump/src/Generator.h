

TCHAR *lpszHash[4]={TEXT("LM"),TEXT("NTLM"),TEXT("DCC v1"),TEXT("DCC v2")};

enum {
  LM_HASH = 0,
  NTLM_HASH,
  DOMAIN_CACHE1,
  DOMAIN_CACHE2
};

void CopySelection( HWND hWnd, UINT uSelection)
{
  LPTSTR  lptstrCopy; 
  HGLOBAL hglbCopy; 
	DWORD	size = 0;
	int		currentItem;
	TCHAR	selectedHash[MAX_PATH];
  TCHAR formattedText[MAX_PATH];
  TCHAR username[MAX_PATH];

  // get the currently selected item
	currentItem = ListView_GetNextItem(GetDlgItem(hWnd,IDC_HASH_LIST),-1,LVNI_SELECTED);

  // make sure it's valid
	if (currentItem == -1) {
		return;
	}

  // get hash of selected item
  ListView_GetItemText(GetDlgItem(hWnd,IDC_HASH_LIST),currentItem,0,selectedHash,MAX_PATH);

  // does user want formatted item?
  if (uSelection == ID_COPY_FORMATTED)
  {
    // get the username and its length
    UINT userLen = GetDlgItemText(hWnd,IDC_HASH_USERNAME,username,MAX_PATH);

    // LM or NTLM hash selected?
    if (currentItem == 0)
    {
      // copy pwdump format to clipboard
      wsprintf(formattedText,
        TEXT("%s:%032x:%s:::"),
        (userLen == 0) ? TEXT("<blank>") : username,
        0,
        selectedHash);
    } else {
      // it's Domain Cache Entry
      wsprintf(formattedText,
        TEXT("%s:%s::%08x:"),
        (userLen == 0) ? TEXT("<blank>") : username,
        selectedHash,
        (currentItem == 1) ? 0 : (GetDlgItemInt(hWnd,IDC_HASH_ITERATIONS,FALSE,FALSE)) << 10);
    }
  } else {
    // just copy the hash itself
    wsprintf(formattedText,TEXT("%s"),selectedHash);
  }

	// Open and Empty the clipboard
  if (!OpenClipboard( hWnd )) 
    return; 
  
  EmptyClipboard(); 

  // get the total length of text
	size = lstrlen( formattedText )+1;
  
  // allocate enough shared memory for this text
  hglbCopy = GlobalAlloc( GMEM_MOVEABLE | GMEM_DDESHARE, size*2 );

  // lock it incase modified during copy procedure
  lptstrCopy = reinterpret_cast<LPTSTR>(GlobalLock(hglbCopy));

  // copy our text to memory
  memcpy(lptstrCopy, formattedText,size*2);

  // unlock
  GlobalUnlock(hglbCopy);

	// Place it in the clipboard
	SetClipboardData(CF_UNICODETEXT, hglbCopy);
  CloseClipboard(); 	
}

/**
    context menu for copying row contents
 */
VOID APIENTRY DisplayContextMenu(HWND hWnd, HWND hList) 
{
  HMENU hMenu; 
  HMENU hMenuTrackPopup;
  POINT pt;
  
  // make sure selected count is only 1
  if (ListView_GetSelectedCount(hList) != 1)
    return;
  
  GetCursorPos(&pt);
  
  // Load the menu resource.
  if ((hMenu = LoadMenu(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_HASH))) == NULL)
    return;
  
  // TrackPopupMenu cannot display the menu bar so get 
  // a handle to the first shortcut menu.
  hMenuTrackPopup = GetSubMenu(hMenu, 0); 
  
  // Display the shortcut menu. Track the right mouse button.
  UINT nCode = TrackPopupMenu(hMenuTrackPopup,TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, hWnd, NULL); 
  
  // if something was selected, copy the row contents
  if (nCode != 0) {
    CopySelection(hWnd, nCode);
  }
  
  DestroyMenu(hMenu); 
} 

/**
      generate binary hash for specified type
 */
size_t GetHash(TCHAR username[], TCHAR password[], DWORD iterations, DWORD dwType, unsigned char hash[])
{
  size_t hashLen = 16;

  switch(dwType)
  {
  case LM_HASH :            // Win95
    {
      cdump->GetLMHash(password,hash);
      break;
    }
  case NTLM_HASH :          // since NT 3.51
    {
      cdump->GetNtlmHash(password,hash);
      break;
    }
  case DOMAIN_CACHE1 :      // Win2k,XP and Win2k3 format
    {
      cdump->GetCachedHash_v1(username,password,hash);
      break;
    }
  case DOMAIN_CACHE2 :      // Vista,Win2k8 and Windows 7 format
    {
      cdump->GetCachedHash_v2(username,password,iterations,hash);
      break;
    }
  default:
    hashLen = 0;
    break;
  }
  return hashLen;
}

VOID GenerateHashes(HWND hParent,HWND hList)
{
  TCHAR username[MAX_PATH];
  TCHAR password[MAX_PATH];
  DWORD iterations = DEFAULT_ITERATION_COUNT;

  ZeroMemory(username,MAX_PATH);
  ZeroMemory(password,MAX_PATH);

  GetDlgItemText(hParent,IDC_HASH_USERNAME,username,MAX_PATH-2);
  GetDlgItemText(hParent,IDC_HASH_PASSWORD,password,MAX_PATH-2);
  iterations = GetDlgItemInt(hParent,IDC_HASH_ITERATIONS,FALSE,FALSE);

  // restrict iterations to 20 preventing computer using up all CPU resources
  if (iterations > 20) {
    SetDlgItemInt(hParent,IDC_HASH_ITERATIONS,DEFAULT_ITERATION_COUNT,FALSE);
    iterations = DEFAULT_ITERATION_COUNT;
  }

  LVITEM item;
  unsigned char hash[128];
  size_t hashLen;
  DWORD dwType[4]={LM_HASH,NTLM_HASH,DOMAIN_CACHE1,DOMAIN_CACHE2};

  item.mask = LVIF_TEXT;
  item.iSubItem = 0;

  for (DWORD i(0);i < sizeof(lpszHash) / sizeof(TCHAR*);i++)
  {
    hashLen = GetHash(username,password,iterations,dwType[i],hash);
    
    TCHAR szHash[MAX_PATH];
    ZeroMemory(szHash,MAX_PATH);

    for (size_t j(0);j < hashLen;j++)
      wsprintf(&szHash[j*2],TEXT("%02x"),hash[j]);

    item.pszText  = szHash;
    item.iItem    = i;
    ListView_SetItem(hList,&item);
  }
}

BOOL CALLBACK HashGenerator(HWND hWnd,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
  HICON hIcon;

  switch(uMsg)
  {
  case WM_INITDIALOG :
    {
      SendDlgItemMessage(hWnd,IDC_HASH_USERNAME,EM_LIMITTEXT,32,0);
			SendDlgItemMessage(hWnd,IDC_HASH_PASSWORD,EM_LIMITTEXT,128,0);
      SendDlgItemMessage(hWnd,IDC_HASH_ITERATIONS,EM_LIMITTEXT,5,0);

      hIcon = LoadIcon(hInst,MAKEINTRESOURCE(IDI_ICON));
      SendMessage(hWnd,WM_SETICON,ICON_SMALL,(LPARAM)hIcon);
      
      LVCOLUMN lvc;
      LVITEM item;
      ZeroMemory(&lvc,sizeof(lvc));
      
      lvc.pszText  = TEXT("Result");
      lvc.mask     = LVCF_TEXT | LVCF_WIDTH;
      lvc.cx       = 220;
      ListView_InsertColumn(GetDlgItem(hWnd,IDC_HASH_LIST),0,&lvc);
      
      lvc.pszText  = TEXT("Format");
      lvc.cx       = 100;
      ListView_InsertColumn(GetDlgItem(hWnd,IDC_HASH_LIST),1,&lvc);

      for(DWORD i(0);i < sizeof(lpszHash) / sizeof(TCHAR*);i++)
      {
        item.mask     = LVIF_TEXT;
        item.pszText  = TEXT("");
        item.iItem    = i;
        item.iSubItem = 0;
        ListView_InsertItem(GetDlgItem(hWnd,IDC_HASH_LIST),&item);

        item.pszText  = lpszHash[i];
        item.iSubItem = 1;
        ListView_SetItem(GetDlgItem(hWnd,IDC_HASH_LIST),&item);
      }

      SetDlgItemInt(hWnd,IDC_HASH_ITERATIONS,10,FALSE);     // 10 is default
      GenerateHashes(hWnd,GetDlgItem(hWnd,IDC_HASH_LIST));
      SetFocus(GetDlgItem(hWnd,IDC_HASH_USERNAME));
      return FALSE;
    }
  case WM_COMMAND :
    {
      switch(LOWORD(wParam))
      {
      case IDC_HASH_USERNAME :
      case IDC_HASH_PASSWORD :
      case IDC_HASH_ITERATIONS :
        {
          if (HIWORD(wParam) == EN_CHANGE)      // parameter has changed
          {
            GenerateHashes(hWnd,GetDlgItem(hWnd,IDC_HASH_LIST));    // update hashes
            break;
          }
        }
      }
      return FALSE;
    }
  case WM_CONTEXTMENU :     // display context only if coming from list window
    {
      if (reinterpret_cast<HWND>(wParam) == GetDlgItem(hWnd,IDC_HASH_LIST)) 
        DisplayContextMenu(hWnd, GetDlgItem(hWnd,IDC_HASH_LIST));
      break;
    }
  case WM_CLOSE :
  case WM_QUIT :
    EndDialog(hWnd,0);
    break;
  default:
    return FALSE;
  }
  return TRUE;
}

