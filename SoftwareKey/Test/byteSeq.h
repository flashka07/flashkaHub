#pragma once
#include <vector>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

class ByteSeq
{
public:
  ByteSeq();
  ByteSeq(const ByteSeq&);
  explicit ByteSeq(BYTE aValue);
  explicit ByteSeq(WORD aValue);
  explicit ByteSeq(DWORD aValue);
  ByteSeq(int aValue);
  ~ByteSeq();

  // exchange values
  void swap(const ByteSeq&);

  template<typename _Type>
  const ByteSeq& setValue(_Type aValue)
  {
    const size_t c_szOfType = sizeof(aValue);
    ByteSeq temp;
    temp.m_pData->reserve(sizeof(c_szOfType));
    BYTE* pValData = reinterpret_cast<BYTE*>(&aValue);
    temp[0] = *pValData;
    for(size_t i=1; i<c_szOfType; ++i)
    {
      temp.m_pData->push_back(*(pValData + i));
    }

    swap(temp);
    return *this;
  }
  const ByteSeq& setByteArray(const BYTE* apValues, size_t aszSize);
  // set bytes from aValue to current, begin at szOffset
  const ByteSeq& overrideAt(size_t aszOffset, const ByteSeq& aValue);

  void appendToSize(size_t aszMaxSize, BYTE abFillValue = 0);
  void shrinkToFit();
  ByteSeq getCropped(size_t aszMaxSize) const;
  ByteSeq getCropped(size_t aszBeginByte, size_t aszEndByte) const;

  size_t getSize() const;
  size_t getRequiredSize() const;

  // shift by N bits value
  void shiftLeft(size_t aszBits);
  void shiftRight(size_t aszBits);

  // integer division
  const ByteSeq& divideBy(const ByteSeq& aDenominator, ByteSeq* apRemainder = NULL);

  // arithmetic operators
  ByteSeq& operator=(const ByteSeq&);
  friend ByteSeq operator+(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend ByteSeq operator-(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend ByteSeq operator*(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend ByteSeq operator/(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend ByteSeq operator%(const ByteSeq& aLhs, const ByteSeq& aRhs);

  const ByteSeq& operator+=(const ByteSeq& aRhs);
  const ByteSeq& operator-=(const ByteSeq& aRhs);
  const ByteSeq& operator*=(const ByteSeq& aRhs);
  const ByteSeq& operator/=(const ByteSeq& aRhs);
  const ByteSeq& operator%=(const ByteSeq& aRhs);

  // shift operators (TODO: instead of size_t use int like used with BYTE)
  ByteSeq operator<<(size_t aszBits) const;
  ByteSeq operator>>(size_t aszBits) const;
  const ByteSeq& operator<<=(size_t aszBits);
  const ByteSeq& operator>>=(size_t aszBits);

  BYTE& operator[](size_t);
  BYTE operator[](size_t) const;

  // boolean operators
  friend bool operator==(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend bool operator!=(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend bool operator>(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend bool operator<(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend bool operator>=(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend bool operator<=(const ByteSeq& aLhs, const ByteSeq& aRhs);

  // bitwise operators
  friend ByteSeq operator&(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend ByteSeq operator|(const ByteSeq& aLhs, const ByteSeq& aRhs);
  friend ByteSeq operator^(const ByteSeq& aLhs, const ByteSeq& aRhs);
  ByteSeq operator~() const;

  friend std::ostream& operator<<(std::ostream& aStream, const ByteSeq& aValue);
  
private:
  void add(BYTE aValue);

  // compare this to aRhs(-1 less, 0 equal, 1 greater)
  int compare(const ByteSeq& aRhs) const;

  template<class _Func>
  static void byteTransform(
    const ByteSeq& aLhs, 
    const ByteSeq& aRhs,
    _Func aOperation,
    ByteSeq& result)
  {
    std::vector<BYTE>::const_iterator iF = aLhs.m_pData->begin();
    std::vector<BYTE>::const_iterator iS = aRhs.m_pData->begin();
    const size_t c_szIterations = std::max(
      aLhs.getRequiredSize(),
      aRhs.getRequiredSize());
    result.appendToSize(c_szIterations);
    std::vector<BYTE>::iterator iR = result.m_pData->begin();
    for(size_t i=0; i<c_szIterations; ++i)
    {
      *iR++ = aOperation(
        (iF != aLhs.m_pData->end()) ? *iF++ : 0,
        (iS != aRhs.m_pData->end()) ? *iS++ : 0);
    }
  }

  std::vector<BYTE>* m_pData;
};