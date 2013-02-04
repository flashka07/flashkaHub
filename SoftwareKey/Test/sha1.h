#pragma once
typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned __int64 QWORD;

namespace sha1
{
  const int c_nSHA1HashSize = 20;

  class ErrorCode
  {
  public:
    static const int success = 0;
    static const int null = 1;
    static const int inputTooLong = 2;
    static const int stateError = 3;
  };

  struct SHA1Context
  {
    QWORD m_qwLength;
    DWORD m_IntermediateHash[c_nSHA1HashSize / 4];
    BYTE m_nBlockIndex;
    BYTE m_Block[64];
    bool m_fComputed;
    int m_nCorrupted;
  };

  int sha1ContextReset(SHA1Context& aContext);
  int sha1Input(
    SHA1Context& aContext,
    const BYTE* apMessage,
    BYTE abLength);
  int sha1Result(
    SHA1Context& aContext,
    BYTE aMessageDigest[c_nSHA1HashSize]);
}