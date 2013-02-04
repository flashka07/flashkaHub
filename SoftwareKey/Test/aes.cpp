#include "aes.h"

namespace aes
{
  template<class _Type>
  BYTE getMostSignBit(_Type a)
  {
    BYTE i = 0;
    _Type tMask = 1U << (sizeof(_Type) * 8) - 1;
    while(!(tMask & a))
    {
      tMask >>= 1;
      ++i;
    }
    return sizeof(_Type) * 8 - i - 1;
  }

  BYTE multi(BYTE a, BYTE b)
  {
    DWORD dwMult = 0;
    BYTE bShiftIteration = 0;
    DWORD dwShifted = 1;
    
    do
    {
      if(dwShifted & b)
        dwMult ^= a << bShiftIteration;
      bShiftIteration++;
      dwShifted <<= 1;
    }
    while(b >= dwShifted);

    // modulus
    const DWORD c_dwIrreducible = 0x011b;
    while(dwMult > 0xff)
    {
      dwMult ^= c_dwIrreducible << (getMostSignBit(dwMult) - 8);
    }

    return dwMult;
  }

  void sumWords(const BYTE a[4], const BYTE b[4], BYTE result[4])
  {
    result[0] = a[0] ^ b[0];
    result[1] = a[1] ^ b[1];
    result[2] = a[2] ^ b[2];
    result[3] = a[3] ^ b[3];
  }

  void multiWords(const BYTE a[4], const BYTE b[4], BYTE result[4])
  {
    result[0] = multi(a[0], b[0]) ^ multi(a[3], b[1]) ^ multi(a[2], b[2]) ^ multi(a[1], b[3]);
    result[1] = multi(a[1], b[0]) ^ multi(a[0], b[1]) ^ multi(a[3], b[2]) ^ multi(a[2], b[3]);
    result[2] = multi(a[2], b[0]) ^ multi(a[1], b[1]) ^ multi(a[0], b[2]) ^ multi(a[3], b[3]);
    result[3] = multi(a[3], b[0]) ^ multi(a[2], b[1]) ^ multi(a[1], b[2]) ^ multi(a[0], b[3]);
  }

  BYTE xtime(BYTE a)
  {
    DWORD dwResult = a << 1;
    return (dwResult & 0x0100) ? static_cast<BYTE>(dwResult) ^ 0x1b : dwResult;
  }

  BYTE getByte(DWORD dwNumber, BYTE abIndex)
  {
    //return number >> (32 - 8 * (bIndex + 1));

    BYTE* pByte = reinterpret_cast<BYTE*>(&dwNumber);
    return *(pByte + (3 - abIndex));
  }

  void getBytes(DWORD number, BYTE result[4])
  {
    /*BYTE* pByte = reinterpret_cast<BYTE*>(&number);
    for(int i=0; i<4; ++i)
      result[i] = *(pByte + i);*/
    for(int i=0; i<4; ++i)
      result[i] = getByte(number, i);
  }

  void setByte(BYTE abByte, BYTE abIndex, DWORD& adwTarget)
  {
    /*adwTarget &= (byte << (32 - 8 * (abIndex + 1))) & 0xffffffff;*/
    BYTE *pBytes = reinterpret_cast<BYTE*>(&adwTarget);
    *(pBytes + (3 - abIndex)) = abByte;
  }

  DWORD setBytes(const BYTE bytes[4])
  {
    //return *reinterpret_cast<const DWORD*>(bytes);
    DWORD dwResult = 0;
    for(int i=0; i<4; ++i)
      setByte(bytes[i], i, dwResult);
    return dwResult;
  }

  const DWORD g_arrRcon[] = 
  {
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1b000000,
    0x36000000,
  };

  const BYTE g_arrSbox[] = 
  {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  };

  const BYTE g_arrInvSbox[] = 
  {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  };

  void setToState(
    const DWORD input[c_bBlockSize],
    BYTE arrState[4][c_bBlockSize])
  {
    /*for(int i=0; i<4; ++i)
      for(int j=0; j<c_bBlockSize; ++j)
        arrState[i][j] = getByte(input[i], j);*/
    for(int i=0; i<c_bBlockSize; ++i)
      setColumnToState(arrState, i, input[i]);
  }

  void getFromState(
    DWORD output[c_bBlockSize],
    const BYTE arrState[4][c_bBlockSize])
  {
    /*for(int i=0; i<4; ++i)
      output[i] = setBytes(arrState[i]);*/
    for(int i=0; i<4; ++i)
      output[i] = getColumnFromState(arrState, i);
  }

  DWORD getColumnFromState(
    const BYTE arrState[4][c_bBlockSize],
    BYTE bIndex)
  {
    BYTE bArr[4] = {0};
    getColumnFromState(arrState, bIndex, bArr);
    return setBytes(bArr);
  }

  void getColumnFromState(
    const BYTE arrState[4][c_bBlockSize],
    BYTE bIndex, 
    BYTE number[4])
  {
    for(int i=0; i<4; ++i)
      number[i] = arrState[i][bIndex];
  }

  void setColumnToState(
    BYTE arrState[4][c_bBlockSize],
    BYTE bIndex, 
    DWORD number)
  {
    for(int i=0; i<4; ++i)
      arrState[i][bIndex] = getByte(number, i);
  }

  void setColumnToState(
    BYTE arrState[4][c_bBlockSize],
    BYTE bIndex, 
    const BYTE number[4])
  {
    setColumnToState(arrState, bIndex, setBytes(number));
  }

  void shiftRows(BYTE arrState[4][c_bBlockSize])
  {
    BYTE arrStateCopy[3][c_bBlockSize] = {0};
    for(int i=1; i<4; ++i)
    {
      for(int j=0; j<c_bBlockSize; ++j)
      {
        arrStateCopy[i - 1][j] = arrState[i][(j + i) % c_bBlockSize];
      }
      for(int j=0; j<c_bBlockSize; ++j)
        arrState[i][j] = arrStateCopy[i - 1][j];
    }
  }

  void invShiftRows(BYTE arrState[4][c_bBlockSize])
  {
    BYTE arrStateCopy[3][c_bBlockSize] = {0};
    for(int i=1; i<4; ++i)
    {
      for(int j=0; j<c_bBlockSize; ++j)
      {
        arrStateCopy[i - 1][(j + i) % c_bBlockSize] = arrState[i][j];
      }
      for(int j=0; j<c_bBlockSize; ++j)
        arrState[i][j] = arrStateCopy[i - 1][j];
    }
  }

  void mixColumnsImpl(
    const BYTE aPolynom[4],
    BYTE arrState[4][c_bBlockSize])
  {
    BYTE bExistColumn[4] = {0};
    BYTE bResultColumn[4] = {0};
    for(BYTE i=0; i<4; ++i)
    {
      getColumnFromState(arrState, i, bExistColumn);
      multiWords(aPolynom, bExistColumn, bResultColumn);
      setColumnToState(arrState, i, bResultColumn);
    }
  }

  void mixColumns(BYTE arrState[4][c_bBlockSize])
  {
    static const BYTE c_bAPolynom[4] = {0x02, 0x01, 0x01, 0x03};
    mixColumnsImpl(c_bAPolynom, arrState);
  }

  void invMixColumns(BYTE arrState[4][c_bBlockSize])
  {
    static const BYTE c_bIAPolynom[4] = {0x0e, 0x09, 0x0d, 0x0b};
    mixColumnsImpl(c_bIAPolynom, arrState);
  }

  BYTE subByte(BYTE aInput, const BYTE aBox[])
  {
    BYTE i = (aInput & 0xf0) >> 4; // HIGH
    BYTE j = aInput & 0x0f; // LOW
    return aBox[16 * i  + j];
  }

  void subBytesImpl(
    const BYTE aBox[],
    BYTE arrState[4][c_bBlockSize])
  {
    for(int i=0; i<4; ++i)
      for(int j=0; j<c_bBlockSize; ++j)
        arrState[i][j] = subByte(arrState[i][j], aBox);
  }

  void subBytes(BYTE arrState[4][c_bBlockSize])
  {
    subBytesImpl(g_arrSbox, arrState);
  }

  void invSubBytes(BYTE arrState[4][c_bBlockSize])
  {
    subBytesImpl(g_arrInvSbox, arrState);
  }

  DWORD rotWord(DWORD word)
  {
    BYTE arrBytes[4] = {0};
    arrBytes[3] = getByte(word, 0);
    for(int i=0; i<3; ++i)
      arrBytes[i] = getByte(word, i+1);

    return setBytes(arrBytes);
  }

  DWORD subWord(DWORD word)
  {
    BYTE arrBytes[4] = {0};
    getBytes(word, arrBytes);
    for(int i=0; i<4; ++i)
      arrBytes[i] = subByte(arrBytes[i], g_arrSbox);

    return setBytes(arrBytes);
  }

  void keyExpansion(
    const BYTE key[4 * c_bKeySize], 
    DWORD words[c_bBlockSize * (c_bRoundsCount + 1)],
    BYTE abKeySize)
  {
    int i = 0;
    for(; i<abKeySize; ++i)
    {
      BYTE arrBytes[4] = 
      {
        key[4 * i],
        key[4 * i + 1],
        key[4 * i + 2],
        key[4 * i + 3],
      };
      words[i] = setBytes(arrBytes);
    }

    DWORD temp = 0;
    for(; i<c_bBlockSize * (c_bRoundsCount + 1); ++i)
    {
      temp = words[i - 1];

      if(!(i % abKeySize))
        temp = subWord(rotWord(temp)) ^ g_arrRcon[i / abKeySize];
      else if((abKeySize > 6) && (i % abKeySize) == 4)
        temp = subWord(temp);

      words[i] = words[i - abKeySize] ^ temp;
    }
  }

  void addRoundKey(
    const DWORD aKeySchedule[c_bBlockSize * (c_bRoundsCount + 1)],
    BYTE abRound,
    BYTE arrState[4][c_bBlockSize])
  {
    for(int i=0; i<4; ++i)
      setColumnToState(arrState, i, getColumnFromState(arrState, i) ^ aKeySchedule[abRound * c_bBlockSize + i]);
  }

  void chipher(
    const DWORD aInput[c_bBlockSize],
    DWORD aOutput[c_bBlockSize],
    const DWORD aKeySchedule[c_bBlockSize * (c_bRoundsCount + 1)])
  {
    BYTE arrState[4][c_bBlockSize] = {0};
    setToState(aInput, arrState);

    addRoundKey(aKeySchedule, 0, arrState);
    for(int i=1; i<c_bRoundsCount; ++i)
    {
      subBytes(arrState);
      shiftRows(arrState);
      mixColumns(arrState);
      addRoundKey(aKeySchedule, i, arrState);
    }

    subBytes(arrState);
    shiftRows(arrState);
    addRoundKey(aKeySchedule, c_bRoundsCount, arrState);

    getFromState(aOutput, arrState);
  }

  void invChipher(
    const DWORD aInput[c_bBlockSize],
    DWORD aOutput[c_bBlockSize],
    const DWORD aKeySchedule[c_bBlockSize * (c_bRoundsCount + 1)])
  {
    BYTE arrState[4][c_bBlockSize] = {0};
    setToState(aInput, arrState);

    addRoundKey(aKeySchedule, c_bRoundsCount, arrState);
    for(int i=c_bRoundsCount-1; i>0; --i)
    {
      invShiftRows(arrState);
      invSubBytes(arrState);
      addRoundKey(aKeySchedule, i, arrState);
      invMixColumns(arrState);
    }

    invShiftRows(arrState);
    invSubBytes(arrState);
    addRoundKey(aKeySchedule, 0, arrState);

    getFromState(aOutput, arrState);
  }
}