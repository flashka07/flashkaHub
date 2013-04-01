#pragma once
#include <string>
#include "../SChannel/tBlob.h"

typedef unsigned int SOCKET;
typedef unsigned char BYTE;

namespace apollo
{
  struct TEncryptState
  {
    TBlob iv;
    BYTE bPos;
  };

  void test_apollo();

  int cryptoaes_test();

  int cryptosign_test();

  int aesCBF_test();

  int encrypt_test(
    const std::string& astrAddress,
    const std::string& astrPort);

  int sendBytes(
    SOCKET aSocket,
    const void* apBuf, 
    size_t aszBuf);

  int receiveBytes(
    SOCKET aSocket,
    void* apBuf, 
    size_t aszBuf, 
    size_t& aszRead,
    unsigned int aunTimeout);
}