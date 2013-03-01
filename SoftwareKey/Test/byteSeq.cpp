#include <algorithm>
#include <ostream>
#include <iomanip>
#include "byteSeq.h"

const WORD c_wBase = std::numeric_limits<BYTE>::max() + 1;

struct _tbitwiseAnd
{
  BYTE operator()(BYTE a, BYTE b)
  {
    return a & b;
  }
} tbitwiseAnd;

struct _tbitwiseOr
{
  BYTE operator()(BYTE a, BYTE b)
  {
    return a | b;
  }
} tbitwiseOr;

struct _tbitwiseXor
{
  BYTE operator()(BYTE a, BYTE b)
  {
    return a ^ b;
  }
} tbitwiseXor;



ByteSeq::ByteSeq()
  :m_pData(new std::vector<BYTE>(1, 0))
{
}

ByteSeq::ByteSeq(const ByteSeq& aRhs)
  :m_pData(new std::vector<BYTE>(*aRhs.m_pData))
{
}

ByteSeq::ByteSeq(BYTE aValue)
  :m_pData(new std::vector<BYTE>)
{
  m_pData->push_back(aValue);
}

ByteSeq::ByteSeq(WORD aValue)
  :m_pData(new std::vector<BYTE>)
{
  m_pData->reserve(sizeof(aValue));
  BYTE* pValData = reinterpret_cast<BYTE*>(&aValue);
  for(size_t i=0; i<sizeof(aValue); ++i)
  {
    m_pData->push_back(*(pValData + i));
  }
}

ByteSeq::ByteSeq(DWORD aValue)
  :m_pData(new std::vector<BYTE>)
{
  m_pData->reserve(sizeof(aValue));
  BYTE* pValData = reinterpret_cast<BYTE*>(&aValue);
  for(size_t i=0; i<sizeof(aValue); ++i)
  {
    m_pData->push_back(*(pValData + i));
  }
}

ByteSeq::ByteSeq(int aValue)
  :m_pData(new std::vector<BYTE>)
{
  //DWORD dwValue = static_cast<DWORD>(aValue);
  m_pData->reserve(sizeof(aValue));
  BYTE* pValData = reinterpret_cast<BYTE*>(&aValue);
  for(size_t i=0; i<sizeof(aValue); ++i)
  {
    m_pData->push_back(*(pValData + i));
  }
}

ByteSeq::~ByteSeq()
{
  if(m_pData)
    delete m_pData;
}

void ByteSeq::swap(const ByteSeq& aRhs)
{
  m_pData->swap(*aRhs.m_pData);
}

const ByteSeq& ByteSeq::setByteArray(const BYTE* apValues, size_t aszSize)
{
  ByteSeq temp;
  temp.m_pData->reserve(aszSize);
  temp[0] = *apValues;
  for(size_t i=1; i<aszSize; ++i)
    temp.m_pData->push_back(*(apValues + i));

  swap(temp);
  return *this;
}

const ByteSeq& ByteSeq::overrideAt(size_t aszOffset, const ByteSeq& aValue)
{
  ByteSeq temp(*this);
  
  const size_t c_szThisSize = temp.getSize();
  const size_t c_szValuesSize = aValue.getSize();
  for(size_t i=0; i<c_szValuesSize; ++i)
  {
    if(i + aszOffset >= c_szThisSize)
      break;
    temp[i + aszOffset] = aValue[i];
  }
  
  
  if(c_szValuesSize + aszOffset > c_szThisSize)
  {
    temp.m_pData->insert(
      temp.m_pData->end(), 
      aValue.m_pData->begin() + c_szThisSize - aszOffset,
      aValue.m_pData->end());
  }

  swap(temp);
  return *this;
}

void ByteSeq::appendToSize(size_t aszMaxSize, BYTE abFillValue)
{
  if(aszMaxSize > getSize())
    m_pData->resize(aszMaxSize, abFillValue);
}

void ByteSeq::shrinkToFit()
{
  m_pData->resize(getRequiredSize());
}

ByteSeq ByteSeq::getCropped(size_t aszMaxSize) const
{
  return getCropped(0, aszMaxSize);
}

ByteSeq ByteSeq::getCropped(size_t aszBeginByte, size_t aszEndByte) const
{
  ByteSeq result;
  result.m_pData->assign(
    m_pData->begin() + aszBeginByte,
    m_pData->begin() + aszEndByte);
  return result;
}

size_t ByteSeq::getSize() const
{
  return m_pData->size();
}

size_t ByteSeq::getRequiredSize() const
{
  size_t szRequired = getSize();
  for(; szRequired > 0 && (*m_pData)[szRequired - 1] == 0; --szRequired);
  return szRequired;
}

void ByteSeq::shiftLeft(size_t aszBits)
{
  if(!aszBits)
    return;

  size_t szZeroesInsert = aszBits / 8;
  ByteSeq temp(*this);

  if(szZeroesInsert)
  {
    std::vector<BYTE> vZeroes(szZeroesInsert);
    temp.m_pData->insert(
      temp.m_pData->begin(),
      vZeroes.begin(),
      vZeroes.end());
  }

  const size_t c_szIterations = temp.getRequiredSize();
  const size_t c_szShiftBits = aszBits - (szZeroesInsert * 8);
  if(c_szShiftBits)
  {
    BYTE bToNext = 0;
    for(size_t i=szZeroesInsert; i<c_szIterations; ++i)
    {
      std::vector<BYTE>::iterator iCur = temp.m_pData->begin() + i;
      BYTE bCurr = *iCur;
      *iCur = (bCurr << c_szShiftBits) | bToNext;
      bToNext = bCurr >> (8 - c_szShiftBits);    
    }

    if(bToNext)
      temp.add(bToNext);
  }

  swap(temp);
}

void ByteSeq::shiftRight(size_t aszBits)
{
  if(!aszBits)
    return;

  const size_t c_szBytesRemove = aszBits / 8;

  ByteSeq temp(*this);
  const size_t c_szInitialSize = temp.getSize();

  if(c_szBytesRemove)
  {
    temp.m_pData->erase(
      temp.m_pData->begin(),
      temp.m_pData->begin() + c_szBytesRemove);
  }

  const size_t c_szIterations = temp.getRequiredSize();
  const size_t c_szShiftBits = aszBits - (c_szBytesRemove * 8);
  if(c_szShiftBits)
  {
    BYTE bToNext = 0;
    for(size_t i=c_szIterations; i>0; --i)
    {
      std::vector<BYTE>::iterator iCur = temp.m_pData->begin() + (i - 1);
      BYTE bCurr = *iCur;
      *iCur = (bCurr >> c_szShiftBits) | bToNext;
      bToNext = bCurr << (8 - c_szShiftBits);    
    }
  }

  temp.appendToSize(c_szInitialSize);
  swap(temp);
}

const ByteSeq& ByteSeq::divideBy(
  const ByteSeq& aDenominator,
  ByteSeq* apRemainder)
{
  const size_t c_szLhsSize = getRequiredSize();
  const size_t c_szRhsSize = aDenominator.getRequiredSize();

  if(c_szLhsSize < c_szRhsSize)
  {
    if(apRemainder)
      *apRemainder = *this;
    *this = 0;
    return *this;
  }

  ByteSeq divisible(*this);
  ByteSeq denominator(aDenominator);

  // step D1
  BYTE d = c_wBase / 
    (static_cast<WORD>(denominator[c_szRhsSize - 1]) + 1);

  // TODO: change mul to shift (need to calc d as power of 2)
  if(d > 1)
  {
    divisible *= d;
    denominator *= d;
  }
  else
  {
    divisible.add(0);
  }

  const size_t c_szMdiff = c_szLhsSize - c_szRhsSize;
  ByteSeq result;
  result.appendToSize(c_szMdiff + 1);
  // step D2
  for(size_t j=c_szMdiff+1; j>0; --j)
  {
    size_t szj = j - 1;
    std::vector<BYTE>::iterator iDiv = divisible.m_pData->begin() 
      + szj + c_szRhsSize - 1;
    std::vector<BYTE>::iterator iDen = denominator.m_pData->begin() 
      + c_szRhsSize - 1;

    // step D3
    WORD wSource = (*(iDiv + 1) * c_wBase + *iDiv);
    WORD q = wSource / *iDen;
    WORD r = wSource % *iDen;
    do
    {
      if(!((q == c_wBase) || 
           (
             (szj > 0) &&
             (c_szRhsSize > 1) &&
             *(iDen - 1) * q > (c_wBase * r + *(iDiv - 1))
           )
         ))
      {
        break;
      }
      --q;
      r += *iDen;
    }
    while(r < c_wBase);

    // step D4
    ByteSeq currendDiv(divisible.getCropped(szj, szj + c_szRhsSize + 1));
    ByteSeq reduce(q * denominator);
    bool fOverflow = false;
    if(currendDiv < reduce)
      fOverflow = true;
    currendDiv -= reduce;

    // step D5
    result[szj] = static_cast<BYTE>(q);
    if(fOverflow)
    {
      // step D6
      --result[szj];
      currendDiv += denominator;
    }

    divisible.overrideAt(szj, currendDiv);
    // step D7
  }
  // step D8
  if(apRemainder)
    *apRemainder = divisible.getCropped(c_szRhsSize).divideBy(d);
  swap(result);
  return *this;
}

const ByteSeq& ByteSeq::pow(const ByteSeq& anExp)
{
  if(anExp == 0)
  {
    swap(ByteSeq(BYTE(1)));
    return *this;
  }

  // step A1
  ByteSeq exp(anExp);
  ByteSeq result(1);
  ByteSeq temp(*this);

  ByteSeq remainder;
  for(; ;)
  {
    // step A2
    exp.divideBy(2, &remainder);
    if(remainder == 0)
    {
      // step A5
      temp *= temp;
      continue;
    }

    // step A3
    result *= temp;

    // step A4
    if(exp == 0)
      break;

    // step A5
    temp *= temp;
  }

  swap(result);
  return *this;
}

ByteSeq& ByteSeq::operator=(const ByteSeq& aRhs)
{
  ByteSeq temp(aRhs);
  swap(temp);
  return *this;
}

ByteSeq operator+(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  const size_t c_szLhsSize = aLhs.getRequiredSize();
  const size_t c_szRhsSize = aRhs.getRequiredSize();
  const ByteSeq* pFirst = NULL;
  const ByteSeq* pSecond = NULL;
  size_t szIterations = 0;
  size_t szNumOfSums = 0;
  if(c_szRhsSize > c_szLhsSize)
  {
    pFirst = &aRhs;
    pSecond = &aLhs;
    szIterations = c_szRhsSize;
    szNumOfSums = c_szLhsSize;
  }
  else
  {
    pFirst = &aLhs;
    pSecond = &aRhs;
    szIterations = c_szLhsSize;
    szNumOfSums = c_szRhsSize;
  }
  
  ByteSeq result(*pFirst);
  bool fOverflow = false;
  size_t i = 0;
  for(; i<szIterations; ++i)
  {
    BYTE bSum = ((i < szNumOfSums) ? (*pSecond)[i] : 0);
    BYTE bResult = result[i] + bSum;
    bool fSumOverflow = bResult < (*pFirst)[i] || bResult < bSum;
    
    if(fOverflow)
      ++bResult;

    result[i] = bResult;

    if(fOverflow)
      fSumOverflow = fSumOverflow || !bResult;
    fOverflow = fSumOverflow;    
  }
  if(fOverflow)
    result.add(1);

  return result;
}

ByteSeq operator-(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  const size_t c_szLhsSize = aLhs.getRequiredSize();
  const size_t c_szRhsSize = aRhs.getRequiredSize();
  
  ByteSeq result(aLhs);
  if(c_szLhsSize < c_szRhsSize)
  {
    result.appendToSize(c_szRhsSize);
  }

  bool fOverflow = false;
  const size_t c_szIterations = result.getSize();
  for(size_t i=0; i<c_szIterations; ++i)
  {
    BYTE bResult = result[i] - ((i < c_szRhsSize) ? aRhs[i] : 0);
    bool fSumOverflow = ((i < c_szLhsSize) ? aLhs[i] : 0) < bResult;

    if(fOverflow)
    {
      fSumOverflow = fSumOverflow || !bResult;
      --bResult;
    }

    result[i] = bResult;
      
    fOverflow = fSumOverflow; 
  }
  return result;
}

ByteSeq operator*(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  const size_t c_szLhsSize = aLhs.getRequiredSize();
  const size_t c_szRhsSize = aRhs.getRequiredSize();

  ByteSeq result;
  result.appendToSize(c_szLhsSize + c_szRhsSize);
  
  for(size_t j=0; j<c_szRhsSize; ++j)
  {
    BYTE bOverflow = 0;
    for(size_t i=0; i<c_szLhsSize; ++i)
    {
      DWORD dwMul = aLhs[i] * aRhs[j] + result[i + j] + bOverflow;
      result[i + j] = dwMul % c_wBase;
      bOverflow = dwMul / c_wBase;
    }
    result[j + c_szLhsSize] = bOverflow;
  }

  return result;
}

ByteSeq operator/(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  ByteSeq result(aLhs);
  return result.divideBy(aRhs);
}

ByteSeq operator%(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  ByteSeq divResult(aLhs);
  ByteSeq modResult;
  divResult.divideBy(aRhs, &modResult);
  return modResult;
}

const ByteSeq& ByteSeq::operator+=(const ByteSeq& aRhs)
{
  *this = *this + aRhs;
  return *this;
}

const ByteSeq& ByteSeq::operator-=(const ByteSeq& aRhs)
{
  *this = *this - aRhs;
  return *this;
}

const ByteSeq& ByteSeq::operator*=(const ByteSeq& aRhs)
{
  *this = *this * aRhs;
  return *this;
}

const ByteSeq& ByteSeq::operator/=(const ByteSeq& aRhs)
{
  *this = *this / aRhs;
  return *this;
}

ByteSeq ByteSeq::operator<<(size_t aszBits) const
{
  ByteSeq temp(*this);
  temp.shiftLeft(aszBits);
  return temp;
}

ByteSeq ByteSeq::operator>>(size_t aszBits) const
{
  ByteSeq temp(*this);
  temp.shiftRight(aszBits);
  return temp;
}

const ByteSeq& ByteSeq::operator<<=(size_t aszBits)
{
  swap(*this << aszBits);
  return *this;
}

const ByteSeq& ByteSeq::operator>>=(size_t aszBits)
{
  swap(*this >> aszBits);
  return *this;
}

BYTE& ByteSeq::operator[](size_t aszOffset)
{
  return (*m_pData)[aszOffset];
}

BYTE ByteSeq::operator[](size_t aszOffset) const
{
  return (*m_pData)[aszOffset];
}

bool operator==(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  const size_t c_szLhsSize = aLhs.getRequiredSize();
  const size_t c_szRhsSize = aRhs.getRequiredSize();

  if(c_szLhsSize != c_szRhsSize)
    return false;

  for(size_t i=0; i<c_szLhsSize; ++i)
  {
    if(aLhs[i] != aRhs[i])
      return false;
  }

  return true;
}

bool operator!=(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  return aLhs.compare(aRhs) != 0;
}

bool operator>(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  return aLhs.compare(aRhs) == 1;
}

bool operator<(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  return aLhs.compare(aRhs) == -1;
}

bool operator>=(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  return aLhs.compare(aRhs) != -1;
}

bool operator<=(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  return aLhs.compare(aRhs) != 1;
}

ByteSeq operator&(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  ByteSeq result;
  ByteSeq::byteTransform(aLhs, aRhs, tbitwiseAnd, result);
  return result;
}

ByteSeq operator|(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  ByteSeq result;
  ByteSeq::byteTransform(aLhs, aRhs, tbitwiseOr, result);
  return result;
}

ByteSeq operator^(const ByteSeq& aLhs, const ByteSeq& aRhs)
{
  ByteSeq result;
  ByteSeq::byteTransform(aLhs, aRhs, tbitwiseXor, result);
  return result;
}

ByteSeq ByteSeq::operator~() const
{
  ByteSeq result;
  const size_t c_szIterations = getSize();
  result.appendToSize(c_szIterations);

  for(size_t i=0; i<c_szIterations; ++i)
    result[i] = ~(*m_pData)[i];
  return result;
}

std::ostream& operator<<(std::ostream& aStream, const ByteSeq& aValue)
{
  aStream << "0x";
  const size_t c_szSize = aValue.getSize();
  for(int i=c_szSize; i>0; --i)
    aStream << std::hex << std::setw(2) << std::setfill('0') 
      << static_cast<DWORD>(aValue[i-1]);
  return aStream;
}

void ByteSeq::add(BYTE aValue)
{
  const size_t c_nId = getRequiredSize();
  if(getSize() == c_nId)
    m_pData->push_back(aValue);
  else
    (*this)[c_nId] = aValue;
}

int ByteSeq::compare(const ByteSeq& aRhs) const
{
  const size_t c_szLhsSize = getRequiredSize();
  const size_t c_szRhsSize = aRhs.getRequiredSize();

  if(c_szLhsSize > c_szRhsSize)
    return 1;
  if(c_szLhsSize < c_szRhsSize)
    return -1;

  for(size_t i=c_szLhsSize; i>0; --i)
  {
    std::vector<BYTE>::const_iterator iFirst = m_pData->begin() + (i - 1);
    std::vector<BYTE>::const_iterator iSecond = aRhs.m_pData->begin() + (i - 1);

    if(*iFirst == *iSecond)
      continue;

    if(*iFirst > *iSecond)
      return 1;
    if(*iFirst < *iSecond)
      return -1;
  }

  return 0;
}

ByteSeq pow(const ByteSeq& aValue, const ByteSeq& aExp)
{
  ByteSeq result(aValue);
  return result.pow(aExp);
}