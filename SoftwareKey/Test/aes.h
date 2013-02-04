#pragma once
typedef unsigned char BYTE;
typedef unsigned int DWORD;

namespace aes
{
  BYTE multi(BYTE a, BYTE b);
  BYTE xtime(BYTE a);
  void sumWords(const BYTE a[4], const BYTE b[4], BYTE result[4]);
  void multiWords(const BYTE a[4], const BYTE b[4], BYTE result[4]);

  BYTE getByte(DWORD number, BYTE bIndex);
  void getBytes(DWORD number, BYTE result[4]);
  void setByte(BYTE byte, BYTE abIndex, DWORD& aTarget);
  DWORD setBytes(const BYTE bytes[4]);

  // AES-128
  const BYTE c_bBlockSize = 4;
  const BYTE c_bKeySize = 4;
  const BYTE c_bRoundsCount = 10;

  void setToState(
    const DWORD input[c_bBlockSize],
    BYTE arrState[4][c_bBlockSize]);
  void getFromState(
    DWORD output[c_bBlockSize],
    const BYTE arrState[4][c_bBlockSize]);
  DWORD getColumnFromState(
    const BYTE arrState[4][c_bBlockSize],
    BYTE bIndex);
  void getColumnFromState(
    const BYTE arrState[4][c_bBlockSize],
    BYTE bIndex, 
    BYTE number[4]);
  void setColumnToState(
    BYTE arrState[4][c_bBlockSize],
    BYTE bIndex, 
    DWORD number);
  void setColumnToState(
    BYTE arrState[4][c_bBlockSize],
    BYTE bIndex, 
    const BYTE number[4]);
  void shiftRows(BYTE arrState[4][c_bBlockSize]);
  void invShiftRows(BYTE arrState[4][c_bBlockSize]);
  void mixColumns(BYTE arrState[4][c_bBlockSize]);
  void invMixColumns(BYTE arrState[4][c_bBlockSize]);
  BYTE subByte(BYTE aInput, const BYTE aBox[]);
  void subBytes(BYTE arrState[4][c_bBlockSize]);
  void invSubBytes(BYTE arrState[4][c_bBlockSize]);
  DWORD rotWord(DWORD word);
  DWORD subWord(DWORD word);
  void addRoundKey(
    const DWORD aKeySchedule[c_bBlockSize * (c_bRoundsCount + 1)],
    BYTE abRound,
    BYTE arrState[4][c_bBlockSize]);

  void keyExpansion(
    const BYTE key[4 * c_bKeySize], 
    DWORD words[c_bBlockSize * (c_bRoundsCount + 1)],
    BYTE abKeySize);
  void chipher(
    const DWORD aInput[c_bBlockSize],
    DWORD aOutput[c_bBlockSize],
    const DWORD aKeySchedule[c_bBlockSize * (c_bRoundsCount + 1)]);
  void invChipher(
    const DWORD aInput[c_bBlockSize],
    DWORD aOutput[c_bBlockSize],
    const DWORD aKeySchedule[c_bBlockSize * (c_bRoundsCount + 1)]);
}