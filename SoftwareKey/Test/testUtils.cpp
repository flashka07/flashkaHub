#include <cmath>
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

  // convert uint (dword) to octet string (base 256)
  int uint2String256(
    DWORD adwNumber,
    char* apOutString,
    size_t aszMaxLength)
  {
    static const double c_dblBase = 256;
    for(size_t i=0; i<aszMaxLength; ++i, ++apOutString)
    {
      DWORD adwChar = adwNumber / std::pow(c_dblBase, static_cast<int>(aszMaxLength - i));
    }
    return 0;
  }
}