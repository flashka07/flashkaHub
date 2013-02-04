#include "testUtils.h"

namespace testUtils
{
  void printArray(BYTE a[4][4])
  {
    for(int i=0; i<4; ++i)
    {
      for(int j=0; j<4; ++j)
        std::cout << " " << std::hex << (DWORD)(a[i][j]);
      std::cout << '\n';
    }
  }
}