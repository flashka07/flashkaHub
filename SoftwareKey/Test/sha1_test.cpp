#include <iostream>
#include "sha1_test.h"

#include "sha1.h"
#include "testUtils.h"

namespace sha1
{
  void test_sha1()
  {
    std::cout << "\nsha1_test:\n\tSHA1(abc)\n";
    SHA1Context context;
    sha1ContextReset(context);

    const BYTE msg[] = "abc";
    int nResult = sha1Input(context, msg, 3);
    std::cout << "sha1Input returned " << nResult << '\n';
    
    BYTE arrMsgDigest[c_nSHA1HashSize] = {0};
    nResult = sha1Result(context, arrMsgDigest);
    std::cout << "sha1Result returned " << nResult 
      << "\nSHA1 = ";
    testUtils::printArray(arrMsgDigest, c_nSHA1HashSize, c_nSHA1HashSize);
    std::cout << "\nMust be: A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D\n";

    std::cout << "\n\tSHA1(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)\n";
    const BYTE msg2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha1ContextReset(context);
    nResult = sha1Input(context, msg2, sizeof(msg2) - 1);
    std::cout << "sha1Input returned " << nResult << '\n';
    
    nResult = sha1Result(context, arrMsgDigest);
    std::cout << "sha1Result returned " << nResult 
      << "\nSHA1 = ";
    testUtils::printArray(arrMsgDigest, c_nSHA1HashSize, c_nSHA1HashSize);
    std::cout << "\nMust be: 84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1\n";
  }
}