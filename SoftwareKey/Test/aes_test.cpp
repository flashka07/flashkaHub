#include "aes_test.h"
#include <iostream>

#include "aes.h"
#include "testUtils.h"

namespace aes
{
  void test_aes()
  {
    multi_test();
    xtime_test();
    sumWords_test();
    shiftRows_test();
    bytesTest();
    keyExpansion_test();
    chipher_test();
    chipher_test2();
  }

  bool multi_test()
  {
    std::cout << "\nmulti_test:\n\t57 multi 83 = ";
    BYTE bResult = multi(0x57, 0x83);
    bool fResult = bResult == 0xc1;
    std::cout << std::hex << static_cast<DWORD>(bResult) 
      << ", must be c1: " << ((fResult) ? "TRUE" : "FALSE")
      << '\n';
    return fResult;
  }

  bool xtime_test()
  {
    std::cout << "\nxtime_test:\n";    

    BYTE bResult = 0x57;
    for(int i=0; i<3; ++i)
    {
      std::cout << "\txtime(" << std::hex 
        << static_cast<DWORD>(bResult) << ") = ";
      bResult = xtime(bResult);
      std::cout << std::hex << static_cast<DWORD>(bResult) << '\n';
    }

    return true;
  }

  bool sumWords_test()
  {
    std::cout << "\nsumWords_test:\n\t{1, 1, 1, 1} + {2, 2, 2, 2} = ";
    BYTE a[4] = {1, 1, 1, 1};
    BYTE b[4] = {2, 2, 2, 2};

    BYTE result[4] = {0};
    sumWords(a, b, result);
    std::cout << std::hex << "{" << (DWORD)result[0] << ", " << (DWORD)result[1] << ", " 
      << (DWORD)result[2] << ", " << (DWORD)result[3] << "}\n";

    return true;
  }

  bool shiftRows_test()
  {
    std::cout << "\nshiftRows_test:\n";
    BYTE a[4][4] = 
    {
      {1, 2, 3, 4},
      {5, 6, 7, 8},
      {9, 10, 11, 12},
      {13, 14, 15, 16},
    };

    DWORD d[4] = 
    {
      setBytes(a[0]),
      setBytes(a[1]),
      setBytes(a[2]),
      setBytes(a[3]),
    };
    testUtils::printArray(a);
    BYTE arrState[4][c_bBlockSize] = {0};
    setToState(d, arrState);
    std::cout << "\nshiftRows\n";
    shiftRows(arrState);

    getFromState(d, arrState);
    a[0][0] = getByte(d[0], 0);
    a[0][1] = getByte(d[0], 1);
    a[0][2] = getByte(d[0], 2);
    a[0][3] = getByte(d[0], 3);
    a[1][0] = getByte(d[1], 0);
    a[1][1] = getByte(d[1], 1);
    a[1][2] = getByte(d[1], 2);
    a[1][3] = getByte(d[1], 3);
    a[2][0] = getByte(d[2], 0);
    a[2][1] = getByte(d[2], 1);
    a[2][2] = getByte(d[2], 2);
    a[2][3] = getByte(d[2], 3);
    a[3][0] = getByte(d[3], 0);
    a[3][1] = getByte(d[3], 1);
    a[3][2] = getByte(d[3], 2);
    a[3][3] = getByte(d[3], 3);
    testUtils::printArray(a);

    std::cout << "\ninvShiftRows\n";
    invShiftRows(arrState);
    getFromState(d, arrState);
    a[0][0] = getByte(d[0], 0);
    a[0][1] = getByte(d[0], 1);
    a[0][2] = getByte(d[0], 2);
    a[0][3] = getByte(d[0], 3);
    a[1][0] = getByte(d[1], 0);
    a[1][1] = getByte(d[1], 1);
    a[1][2] = getByte(d[1], 2);
    a[1][3] = getByte(d[1], 3);
    a[2][0] = getByte(d[2], 0);
    a[2][1] = getByte(d[2], 1);
    a[2][2] = getByte(d[2], 2);
    a[2][3] = getByte(d[2], 3);
    a[3][0] = getByte(d[3], 0);
    a[3][1] = getByte(d[3], 1);
    a[3][2] = getByte(d[3], 2);
    a[3][3] = getByte(d[3], 3);
    testUtils::printArray(a);

    return true;
  }

  bool bytesTest()
  {
    std::cout << "\nbytesTest:\n";
    std::cout << "setBytes:\n";
    BYTE a[4] = {0x8e, 0x73, 0xb0, 0xf7};
    testUtils::printArray(a, 4, 4);
    std::cout << "\nresult is " << setBytes(a) << '\n';

    std::cout << "getBytes:\n";
    DWORD d = 0x6452c810;
    std::cout << "for 0x6452c810 result is\n";
    getBytes(d, a);
    testUtils::printArray(a, 4, 4);
    std::cout << '\n';

    return true;
  }

  bool keyExpansion_test()
  {
    std::cout << "\nkeyExpansion_test:\n";
    BYTE key[4 * c_bKeySize] =
    {
      0x2b, 0x7e, 0x15, 0x16, 
      0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88,
      0x09, 0xcf, 0x4f, 0x3c
    };

    testUtils::printArray(key, 4 * c_bKeySize, c_bKeySize);

    DWORD roundKeys[c_bBlockSize * (c_bRoundsCount + 1)] = {0};
    keyExpansion(key, roundKeys, c_bKeySize);
    std::cout << "\nkeyExpansion:\n";
    testUtils::printArray(roundKeys, c_bBlockSize * (c_bRoundsCount + 1), 6);
    return true;
  }

  bool chipher_test()
  {
    std::cout << "\nchipher_test:\n";
    BYTE key[4 * c_bKeySize] =
    {
      0x2b, 0x7e, 0x15, 0x16, 
      0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88,
      0x09, 0xcf, 0x4f, 0x3c
    };

    DWORD roundKeys[c_bBlockSize * (c_bRoundsCount + 1)] = {0};
    keyExpansion(key, roundKeys, c_bKeySize);

    DWORD arrInput[c_bBlockSize] = 
    {
      0x3243f6a8,
      0x885a308d,
      0x313198a2,
      0xe0370734
    };
    DWORD arrOutput[c_bBlockSize] = {0};

    std::cout << "input:\n";
    testUtils::printArray(arrInput, c_bBlockSize, c_bBlockSize);

    chipher(arrInput, arrOutput, roundKeys);
    std::cout << "\nencrypted:\n";
    testUtils::printArray(arrOutput, c_bBlockSize, c_bBlockSize);

    invChipher(arrOutput, arrInput, roundKeys);
    std::cout << "\ndecrypted:\n";
    testUtils::printArray(arrInput, c_bBlockSize, c_bBlockSize);
    return true;
  }

  bool chipher_test2()
  {
    std::cout << "\nchipher_test:\n";
    BYTE key[4 * c_bKeySize] =
    {
      0x00, 0x01, 0x02, 0x03, 
      0x04, 0x05, 0x06, 0x07, 
      0x08, 0x09, 0x0a, 0x0b, 
      0x0c, 0x0d, 0x0e, 0x0f
    };

    DWORD roundKeys[c_bBlockSize * (c_bRoundsCount + 1)] = {0};
    keyExpansion(key, roundKeys, c_bKeySize);

    DWORD arrInput[c_bBlockSize] = 
    {
      0x00112233,
      0x44556677,
      0x8899aabb,
      0xccddeeff
    };
    DWORD arrOutput[c_bBlockSize] = {0};

    std::cout << "input:\n";
    testUtils::printArray(arrInput, c_bBlockSize, c_bBlockSize);

    chipher(arrInput, arrOutput, roundKeys);
    std::cout << "\nencrypted:\n";
    testUtils::printArray(arrOutput, c_bBlockSize, c_bBlockSize);

    invChipher(arrOutput, arrInput, roundKeys);
    std::cout << "\ndecrypted:\n";
    testUtils::printArray(arrInput, c_bBlockSize, c_bBlockSize);
    return true;
  }
}