#include <memory>
#include "sha1.h"

namespace sha1
{
  void sha1PadMessage(SHA1Context& aContext);
  void sha1ProcessBlock(SHA1Context& aContext);

  template<class _Type>
  _Type circularShift(_Type aWord, int anBits)
  {
    return (aWord << anBits) | 
      (aWord >> (sizeof(aWord) * 8 - anBits));
  }

  int sha1ContextReset(SHA1Context& aContext)
  {
    std::memset(aContext.m_Block, 0, 64);
    aContext.m_nBlockIndex = 0;
    aContext.m_fComputed = false;
    aContext.m_IntermediateHash[0] = 0x67452301;
    aContext.m_IntermediateHash[1] = 0xEFCDAB89;
    aContext.m_IntermediateHash[2] = 0x98BADCFE;
    aContext.m_IntermediateHash[3] = 0x10325476;
    aContext.m_IntermediateHash[4] = 0xC3D2E1F0;
    aContext.m_nCorrupted = ErrorCode::success;
    aContext.m_qwLength = 0;

    return ErrorCode::success;
  }

  int sha1Input(
    SHA1Context& aContext,
    const BYTE* apMessage,
    BYTE abLength)
  {
    if(!abLength)
      return ErrorCode::success;

    if(!apMessage)
      return ErrorCode::null;

    if(aContext.m_fComputed)
    {
      aContext.m_nCorrupted = ErrorCode::stateError;
      return ErrorCode::stateError;
    }

    if(aContext.m_nCorrupted)
      return aContext.m_nCorrupted;

    while(abLength-- && !aContext.m_nCorrupted)
    {
      aContext.m_Block[aContext.m_nBlockIndex++] = (*apMessage & 0xff);
      aContext.m_qwLength += 8;
      if(!aContext.m_qwLength)
        return ErrorCode::inputTooLong;

      if(aContext.m_nBlockIndex == 64)
        sha1ProcessBlock(aContext);

      ++apMessage;
    }

    return ErrorCode::success;
  }

  int sha1Result(
    SHA1Context& aContext,
    BYTE aMessageDigest[c_nSHA1HashSize])
  {
    if(!aMessageDigest)
      return ErrorCode::null;

    if(aContext.m_nCorrupted)
      return aContext.m_nCorrupted;

    if(!aContext.m_fComputed)
    {
      sha1PadMessage(aContext);
      for(int i=0; i<64; ++i)
        aContext.m_Block[i] = 0;
      aContext.m_qwLength = 0;
      aContext.m_fComputed = true;
    }

    for(int i=0; i<c_nSHA1HashSize; ++i)
    {
      aMessageDigest[i] = aContext.m_IntermediateHash[i >> 2]
        >> 8 * (3 - (i & 0x03));
    }

    return ErrorCode::success;
  }
  
  void sha1PadMessage(SHA1Context& aContext)
  {
    if(aContext.m_nBlockIndex > 55)
    {
      aContext.m_Block[aContext.m_nBlockIndex++] = 0x80;
      while(aContext.m_nBlockIndex < 64)
        aContext.m_Block[aContext.m_nBlockIndex++] = 0;

      sha1ProcessBlock(aContext);

      while(aContext.m_nBlockIndex < 56)
        aContext.m_Block[aContext.m_nBlockIndex++] = 0;
    }
    else
    {
      aContext.m_Block[aContext.m_nBlockIndex++] = 0x80;
      while(aContext.m_nBlockIndex < 56)
        aContext.m_Block[aContext.m_nBlockIndex++] = 0;
    }

    aContext.m_Block[56] = aContext.m_qwLength >> 56;
    aContext.m_Block[57] = aContext.m_qwLength >> 48;
    aContext.m_Block[58] = aContext.m_qwLength >> 40;
    aContext.m_Block[59] = aContext.m_qwLength >> 32;
    aContext.m_Block[60] = aContext.m_qwLength >> 24;
    aContext.m_Block[61] = aContext.m_qwLength >> 16;
    aContext.m_Block[62] = aContext.m_qwLength >> 8;
    aContext.m_Block[63] = aContext.m_qwLength;

    sha1ProcessBlock(aContext);
  }

  void sha1ProcessBlock(SHA1Context& aContext)
  {
    static const DWORD c_KNumbers[] = 
    {
      0x5A827999,
      0x6ED9EBA1,
      0x8F1BBCDC,
      0xCA62C1D6
    };

    DWORD arrWords[80];
    for(int i=0; i<16; ++i)
    {
      arrWords[i] = (aContext.m_Block[i * 4] << 24)
        | (aContext.m_Block[i * 4 + 1] << 16)
        | (aContext.m_Block[i * 4 + 2] << 8)
        | (aContext.m_Block[i * 4 + 3]);
    }

    for(int i=16; i<80; ++i)
      arrWords[i] = circularShift(
        arrWords[i - 3] ^ arrWords[i - 8] ^ arrWords[i - 14] ^ arrWords[i - 16],
        1);

    DWORD a = aContext.m_IntermediateHash[0];
    DWORD b = aContext.m_IntermediateHash[1];
    DWORD c = aContext.m_IntermediateHash[2];
    DWORD d = aContext.m_IntermediateHash[3];
    DWORD e = aContext.m_IntermediateHash[4];

    for(int i=0; i<20; ++i)
    {
      DWORD dwTemp = circularShift(a, 5) + ((b & c) | ((~b) & d))
        + e + arrWords[i] + c_KNumbers[0];
      e = d;
      d = c;
      c = circularShift(b, 30);
      b = a;
      a = dwTemp;
    }

    for(int i=20; i<40; ++i)
    {
      DWORD dwTemp = circularShift(a, 5) + (b ^ c ^ d)
        + e + arrWords[i] + c_KNumbers[1];
      e = d;
      d = c;
      c = circularShift(b, 30);
      b = a;
      a = dwTemp;
    }

    for(int i=40; i<60; ++i)
    {
      DWORD dwTemp = circularShift(a, 5) + ((b & c) | (b & d) | (c & d))
        + e + arrWords[i] + c_KNumbers[2];
      e = d;
      d = c;
      c = circularShift(b, 30);
      b = a;
      a = dwTemp;
    }

    for(int i=60; i<80; ++i)
    {
      DWORD dwTemp = circularShift(a, 5) + + (b ^ c ^ d)
        + e + arrWords[i] + c_KNumbers[3];
      e = d;
      d = c;
      c = circularShift(b, 30);
      b = a;
      a = dwTemp;
    }

    aContext.m_IntermediateHash[0] += a;
    aContext.m_IntermediateHash[1] += b;
    aContext.m_IntermediateHash[2] += c;
    aContext.m_IntermediateHash[3] += d;
    aContext.m_IntermediateHash[4] += e;

    aContext.m_nBlockIndex = 0;
  }
}