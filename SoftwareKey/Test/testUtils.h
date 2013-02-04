#pragma once
#include <iostream>
typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned __int64 QWORD;

namespace testUtils
{
  void printArray(BYTE a[4][4]);

  template<class _Type>
  void printArray(_Type arr, size_t aszLength, size_t aszRow)
  {
    for(int i=0; i<aszLength; ++i)
    {
      if(i && !(i % aszRow))
        std::cout << '\n';
      std::cout << " " << std::hex << (DWORD)(arr[i]);
    }
  }
}