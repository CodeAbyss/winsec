


HWND hSamWnd;
HTREEITEM hSamTreeItem;

// display status of current window
TCHAR *sam_status = TEXT("");

/**
 * 
 *  Initialize the SAM window columns
 *
 */
void initSAM()
{
	LVCOLUMN lvc;
	
	hSamWnd           = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,WC_LISTVIEW,NULL,LVS_SINGLESEL | LVS_REPORT | WS_CHILD | WS_VISIBLE,0,0,0,0,hMainWnd,NULL,hInst,NULL);
	tvis.item.lParam  = reinterpret_cast<LPARAM>(hSamWnd);
	tvis.item.pszText = TEXT("SAM LM/NT Hashes");
	hSamTreeItem      = TreeView_InsertItem(hTreeWnd, &tvis);

	lvc.pszText = TEXT("User Name");
	lvc.mask    = LVCF_TEXT | LVCF_WIDTH;
	lvc.cx      = 120;
	ListView_InsertColumn(hSamWnd,0,&lvc);

	lvc.cx      = 220;
	lvc.pszText = TEXT("LM");
	ListView_InsertColumn(hSamWnd,1,&lvc);

	lvc.pszText = TEXT("NTLM");
	lvc.cx      = 220;
	ListView_InsertColumn(hSamWnd,2,&lvc);

  lvc.pszText = TEXT("Full Name");
  lvc.cx      = 120;
  ListView_InsertColumn(hSamWnd,3,&lvc);

	lvc.pszText = TEXT("Comment");
	lvc.cx = 250;
	ListView_InsertColumn(hSamWnd,4,&lvc);

	ListView_SetExtendedListViewStyle(hSamWnd,LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

/**
 *
 * dump SAM NTLM / LM hashes
 *
 * local hashes only, domain hashes aren't stored in registry.
 *
 */

void dump_sam()
{
  LVITEM item;
  TCHAR buffer[128];

  // get the SAM key first
  if (cdump->GetSamKey())
  {
    // if that was good, get available entries
    SAM_LIST *slist = cdump->GetSamEntries();

    // if none were retrieved, 
    if (slist == NULL)
    {
      sam_status = TEXT("No SAM entries found.");
    }
    else
    {
      DWORD dwIndex = 0;
      for (SAM_LIST *entries = slist;entries != NULL;entries = entries->next)
      {
				item.mask  = LVIF_TEXT;
				item.iItem = dwIndex++;

        // get entry
        SAM_ENTRY *user_entry = entries->entry;

        item.pszText = user_entry->UserName;
				item.iSubItem = 0;
				ListView_InsertItem(hSamWnd,&item);

        if (user_entry->SamPasswords.SecretPasswords.LmPasswordPresent)
        {
          for (int i(0);i < 16;i++)
            wsprintf(&buffer[2*i],TEXT("%02x"),user_entry->SamPasswords.SecretPasswords.EncryptedLmOwfPassword.data[i]);
        }
        else // blank password hash
        {
          wsprintf(buffer,TEXT("%s"),TEXT("aad3b435b51404eeaad3b435b51404ee"));
        }

        item.iSubItem++;
        item.pszText = buffer;
        ListView_SetItem(hSamWnd,&item);
        
        if (user_entry->SamPasswords.SecretPasswords.NtPasswordPresent)
        {
          for (int i(0);i < 16;i++)
            wsprintf(&buffer[2*i],TEXT("%02x"),user_entry->SamPasswords.SecretPasswords.EncryptedNtOwfPassword.data[i]);
        }
        else // blank password hash
        {
          wsprintf(buffer,TEXT("%s"),TEXT("31d6cfe0d16ae931b73c59d7e0c089c0"));
        }

        item.iSubItem++;
        item.pszText = buffer;
        ListView_SetItem(hSamWnd,&item);

        item.iSubItem++;
        item.pszText = user_entry->FullName;
        ListView_SetItem(hSamWnd,&item);

        item.iSubItem++;
        item.pszText = user_entry->Comment;
        ListView_SetItem(hSamWnd,&item);
      }
    }
  }
}
