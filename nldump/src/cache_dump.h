


HWND hCacheWnd;
HTREEITEM hCacheTreeItem;

// display status of current window
TCHAR *cache_status = TEXT("");

/**
 * 
 *  Initialize the Domain Cache Credentials window columns
 *
 */
void initCACHE()
{
	LVCOLUMN lvc;
	ZeroMemory(&lvc,sizeof(lvc));

	hCacheWnd         = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,WC_LISTVIEW,NULL,LVS_SINGLESEL | LVS_REPORT | WS_CHILD,0,0,0,0,hMainWnd,NULL,hInst,NULL);
	tvis.item.lParam  = reinterpret_cast<LPARAM>(hCacheWnd);
	tvis.item.pszText = TEXT("Domain Cached Credentials");
	hCacheTreeItem    = TreeView_InsertItem(hTreeWnd, &tvis);

  lvc.mask     = LVCF_TEXT | LVCF_WIDTH;

  lvc.pszText  = TEXT("Domain");
  lvc.cx       = 60;
  ListView_InsertColumn(hCacheWnd,0,&lvc);

	lvc.pszText  = TEXT("User Name");
	lvc.cx       = 100;
	ListView_InsertColumn(hCacheWnd,1,&lvc);

	lvc.pszText  = TEXT("Cached Credentials");
	lvc.cx       = 220;
	ListView_InsertColumn(hCacheWnd,2,&lvc);

	lvc.pszText  = TEXT("Iterations");
	lvc.cx       = 65;
	ListView_InsertColumn(hCacheWnd,3,&lvc);

	lvc.pszText  = TEXT("Full Name");
	lvc.cx       = 150;
	ListView_InsertColumn(hCacheWnd,4,&lvc);

	lvc.pszText  = TEXT("Last Login");
	lvc.cx       = 80;
	ListView_InsertColumn(hCacheWnd,5,&lvc);

	ListView_SetExtendedListViewStyle(hCacheWnd,LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

/**
 *
 * Dump Domain Cache Credentials
 *
 * Only useful for machine part of windows domain
 *
 */

void dump_cache()
{
  LVITEM item;
  TCHAR buffer[128];
  
  // get the cache key, assuming we've already retrieved Syskey + LSA database key
  if (cdump->GetCachedKey())
  {
    // see if any entries available.
    CACHE_LIST *clist = cdump->GetCachedEntries();

    // if none found, set the status bar message to tell user
    if (clist == NULL)
    {
      cache_status = TEXT("No domain cached hashes found.");
    }
    else
    {
      // undocumented iteration count is only applicable since Vista
      DWORD dwIterations = cdump->GetIterationCount() << 10;

      DWORD dwIndex = 0;
      for (CACHE_LIST *entries = clist;entries != NULL;entries = entries->next)
      {
        // get one entry
        USER_ENTRY *entry = entries->entry;

        item.iItem    = dwIndex;
        item.mask     = LVIF_TEXT;

        // Domain
        item.pszText  = entry->domain;
        item.iSubItem = 0;
        ListView_InsertItem(hCacheWnd,&item);

        // User Name
        item.pszText  = entry->id;
        item.iSubItem++;
        ListView_SetItem(hCacheWnd,&item);

        // Domain Cache hash
        for (int i(0);i < 16;i++)
          wsprintf(&buffer[i*2],TEXT("%02x"),entry->hashes.SecretPasswords.EncryptedNtOwfPassword.data[i]);

        item.pszText  = buffer;
        item.iSubItem++;
        ListView_SetItem(hCacheWnd,&item);

        // Iterations (if any)
        wsprintf(buffer,TEXT("%i"),dwIterations);
        item.pszText  = buffer;
        item.iSubItem++;
        ListView_SetItem(hCacheWnd,&item);

        // Full Name
        item.pszText  = entry->fullName;
        item.iSubItem++;
        ListView_SetItem(hCacheWnd,&item);

        // Last Logon
        wchar_t last_logon[MAX_PATH];
        bool bTime = GetDateFormatW(LOCALE_SYSTEM_DEFAULT,0,&entry->time,TEXT("MM/dd/yyyy"),last_logon,MAX_PATH);

        // format failed? display Unknown
        wsprintf(buffer,TEXT("%s"),(bTime) ? last_logon : TEXT("Unknown"));

        item.pszText  = buffer;
        item.iSubItem++;
        ListView_SetItem(hCacheWnd,&item);
      }
    }
  }
  else if (cdump->GetErrorCode() == ERROR_FILE_NOT_FOUND)
  {
    cache_status = TEXT("No Domain Cache Key found.");
  }
  else if(cdump->GetErrorCode() == ERROR_BAD_LENGTH)
  {
    cache_status = TEXT("Invalid Syskey.");
  }
  else
  {
    // "\nError obtaining Domain Cache Key: %i\n",cdump->GetErrorCode());
  }
}
