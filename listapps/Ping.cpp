
#include "ping.h"

// sort in names of applications in ascending order
bool SortByName(product_info rpStart, product_info rpEnd)
{
  return ( lstrcmp( rpStart.name.c_str(), rpEnd.name.c_str() ) < 0);
}


