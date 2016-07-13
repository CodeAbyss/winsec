
#ifndef DUMPER_H
#define DUMPER_H

#include "Cache.h"
#include "Sam.h"

class Dumper : public Cache, public Sam {
  public:
    Dumper();
    ~Dumper();
};

#endif
