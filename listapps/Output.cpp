
void SaveToFile(FILE* out, class Machine *pMachine)
{
  AppList *pList = pMachine->pList;

  wchar_t *app_format = new wchar_t[pList->nPublisher + pList->nVersion + pList->nName + 64];

  swprintf(app_format,L"\n%%-%ds  %%-%ds  %%-%ds",pMachine->pList->nName,
           pMachine->pList->nPublisher,pMachine->pList->nVersion);
  
  fwprintf(out,app_format,L"Application Name",L"Publisher",L"Version");
  fwprintf(out,app_format,L"================",L"=========",L"=======");

  for (vector<product_info>::const_iterator it = pMachine->pList->products.begin();it != pMachine->pList->products.end();it++) {
    if (it->bImage) continue;
    fwprintf(out,app_format,it->name.c_str(),it->publisher.c_str(),it->version.c_str());
  }
  delete []app_format;
}

void SaveAsTXT(class Machine *pMachine)
{
  // open for write
  FILE *out = _wfopen((pMachine->GetHostName() + L".txt").c_str(),L"w");
  
  if (out == NULL) {
    wprintf(L"\n\n\tCouldn't save to TXT file..listing on screen instead\n");
    ListOnScreen(pMachine);
  } else {
    SaveToFile(out,pMachine);
    wprintf(L"\n\n\tSaved %d entries to %s\n",pMachine->pList->products.size(),
           (pMachine->GetHostName() + L".txt").c_str());
    fclose(out);
  }
}

void SaveAsCSV(class Machine *pMachine)
{
  // open for write
  FILE *out = _wfopen((pMachine->GetHostName() + L".csv").c_str(),L"w");
  
  if (out == NULL) {
    wprintf(L"\n\n\tCouldn't save to CSV file..check your permissions or if file already exists\n");
  } else {
    for (vector<product_info>::const_iterator it = pMachine->pList->products.begin();it != pMachine->pList->products.end();it++) {
      
      if (it->bImage) continue;

      wstring name      = it->name;
      wstring publisher = it->publisher;
      wstring version   = it->version;
      
      wstring::size_type found;
      while((found = name.find_first_of(L',')) != wstring::npos) name[found] = L'.';
      while((found = publisher.find_first_of(L',')) != wstring::npos) publisher[found] = L'.';

      fwprintf(out,L"%s,%s,%s\n",
        name.empty()      ? L"<unspecified>" : name.c_str(),
        publisher.empty() ? L"<unspecified>" : publisher.c_str(),
        version.empty()   ? L"<unspecified>" : version.c_str());
        
    }
    wprintf(L"\n\n\tSaved %d entries to %s\n",pMachine->pList->products.size(),
           (pMachine->GetHostName() + L".csv").c_str());
    fclose(out);
  }
}

void replace_special(wstring &str)
{
  wstring copyright  = L"©";
  wstring trademark  = L"™";
  wstring ampersand  = L"&";
  wstring registered = L"®";

  if (str.find(registered) != wstring::npos)
      str.replace(str.find(registered),registered.length(),L"&reg;");

  if (str.find(ampersand) != wstring::npos)
      str.replace(str.find(ampersand),ampersand.length(),L"&amp;");

  if (str.find(copyright) != wstring::npos)
      str.replace(str.find(copyright),copyright.length(),L"&copy;");

  if (str.find(trademark) != wstring::npos)
      str.replace(str.find(trademark),trademark.length(),L"&#8482;");
}

void SaveAsHTML(class Machine *pMachine)
{
  // open for write
  FILE *out = _wfopen((pMachine->GetHostName() + L".html").c_str(),L"w");
  
  if (out == NULL) {
    wprintf(L"\n\n\tCouldn't save to HTML file..listing on screen instead\n");
    ListOnScreen(pMachine);
  } else {
    wstring header = L"<html><head><title>List of applications on " 
      + pMachine->GetHostName() 
      + L"</title></head><body><table border=\"1\">"
      + L"<tr>"
      + L"<th>Application Name</th>"
      + L"<th>Publisher</th>"
      + L"<th>Version</th>"
      + L"</tr>";

    fwprintf(out,header.c_str());
    int i = 0;

    for (vector<product_info>::iterator it = pMachine->pList->products.begin();it != pMachine->pList->products.end();it++) {
      
      if (it->bImage) continue;

      wstring name      = it->name;
      wstring publisher = it->publisher;

      // replace any copyright/trademark/registered symbols
      // with html code
      replace_special(name);
      replace_special(publisher);

      wstring entry = ((i++ % 2) ? L"\n<tr>" : L"\n<tr bgcolor=#cccccc>")
                   + (L"<td>" + name      + L"</td>")
                   + (L"<td>" + (publisher.empty()   ? L"unspecified" : publisher)   + L"</td>")
                   + (L"<td>" + (it->version.empty() ? L"unspecified" : it->version) + L"</td>")
                   +  L"</tr>";

      fwprintf(out,entry.c_str());
    }
    fwprintf(out,L"</body></html>");

    wprintf(L"\n\n\tSaved %d entries to %s\n",pMachine->pList->products.size(),
           (pMachine->GetHostName() + L".HTML").c_str());
    fclose(out);
  }
}

void ListOnScreen(class Machine *pMachine)
{
  class AppList *pList = pMachine->pList;

  // set the console screen buffer so we see everything properly
  CONSOLE_SCREEN_BUFFER_INFO cbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&cbi);
  cbi.dwSize.X  = (SHORT)(pList->nName + pList->nPublisher + pList->nVersion + 8);  // width
  cbi.dwSize.Y += (SHORT)(pList->products.size() + 5);                              // length
  SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE),cbi.dwSize);

  wprintf(L"\n\n\tListing %d entries.\n",pList->products.size());
  SaveToFile(stdout,pMachine);
}
