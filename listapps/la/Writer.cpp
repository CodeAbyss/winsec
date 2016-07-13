

// check and replace any characters/symbols that cause problems in HTML format
// replace with HTML code equivilant
// not a complete list, but includes most encountered to date..
void rep_sym(std::wstring &str)
{
  std::wstring c = L"©";
  std::wstring t = L"™";
  std::wstring a = L"&";
  std::wstring r = L"®";

  if(str.find(r) != std::wstring::npos)
     str.replace(str.find(r),r.length(),L"&reg;");

  if(str.find(a) != std::wstring::npos)
     str.replace(str.find(a),a.length(),L"&amp;");

  if(str.find(c) != std::wstring::npos)
     str.replace(str.find(c),c.length(),L"&copy;");

  if(str.find(t) != std::wstring::npos)
     str.replace(str.find(t),t.length(),L"&#8482;");
}

bool Products::writeToHTML(std::wstring filename)
{
  // return if nothing to save
  if(entries.size() == 0) {
    dwError = ERROR_BAD_LENGTH;
    return false;
  }

  // open file for write access
  FILE *out = _wfopen(((filename.empty() ? host : filename) + L".html").c_str(),L"w");
  
  // return if not opened
  if(out == NULL) {
    dwError = GetLastError();
    return false;
  }
  
  // format the header
  std::wstring header = L"<html><head><title>"
                      + filename
                      + L"</title></head><body><table border=\"1\">"
                      + L"<tr>"
                      + L"<th>Application Name</th>"
                      + L"<th>Publisher</th>"
                      + L"<th>Version</th>"
                      + L"</tr>";
  fwprintf(out,header.c_str());
  
  int i = 0;

  // print the list
  for(std::vector<ProductEntry>::iterator it = entries.begin();it != entries.end();it++) {

    if(it->bFilter) continue;

    std::wstring name      = it->name;
    std::wstring publisher = it->publisher;

    // replace any copyright/trademark/registered symbols with html code
    rep_sym(name);
    rep_sym(publisher);

    std::wstring entry = ((i++ % 2) ? L"\n<tr>" : L"\n<tr bgcolor=#cccccc>")
                         + (L"<td>" + name      + L"</td>")
                         + (L"<td>" + (publisher.empty()   ? L"unspecified" : publisher)   + L"</td>")
                         + (L"<td>" + (it->version.empty() ? L"unspecified" : it->version) + L"</td>")
                         +  L"</tr>";

    fwprintf(out,entry.c_str());
  }
  fwprintf(out,L"</body></html>");
  fclose(out);
  dwError = ERROR_SUCCESS;
  
  return true;
}

// write the list of products to a text file
bool Products::writeToTXT(std::wstring filename)
{
  // return if nothing to save
  if(entries.size() == 0) {
    dwError = ERROR_BAD_LENGTH;
    return false;
  }

  // open file for write access
  // if no filename is specified, use the hostname
  FILE *out = _wfopen(((filename.empty() ? host : filename) + L".txt").c_str(),L"w");
  
  // return if not opened
  if(out == NULL) {
    dwError = GetLastError();
    return false;
  }

  writeToFile(out);
  fclose(out);
  
  dwError = ERROR_SUCCESS;
  return true;
}

// be careful to set nPublisher, nVersion and nName before calling this..
void Products::writeToFile(FILE* out)
{
  wchar_t *fmt = new wchar_t[nPublisher + nVersion + nName + 32];

  swprintf(fmt,L"\n%%-%ds  %%-%ds  %%-%ds",nName,nPublisher,nVersion);
  
  fwprintf(out,fmt,L"Application Name",L"Publisher",L"Version");
  fwprintf(out,fmt,L"================",L"=========",L"=======");

  for(std::vector<ProductEntry>::const_iterator it = entries.begin();it != entries.end();it++) {
    if (it->bFilter) continue;

    fwprintf(out,fmt,it->name.c_str(),it->publisher.c_str(),it->version.c_str());
  }
  delete []fmt;
}
