#pragma once
#include "byteSeq.h"

namespace rsa
{
  struct RSAPublicKey
  {
    ByteSeq m_bsN;
    ByteSeq m_bsE;
  };

  struct RSAPrivateKey
  {
    ByteSeq m_bsN;
    ByteSeq m_bsD;
  };
}