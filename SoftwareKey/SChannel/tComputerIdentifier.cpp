#include <string>
bool operator==(
  const std::wstring& aLhs,
  const std::wstring& aRhs);

#include "tComputerIdentifier.h"

TComputerIdentifier::TComputerIdentifier()
{
}

TComputerIdentifier::~TComputerIdentifier()
{
}

bool operator==(
  const std::wstring& aLhs,
  const std::wstring& aRhs)
{
  return !aLhs.compare(aRhs);
}

bool TComputerIdentifier::isEqual(
  const TComputerIdentifier& aAnother) const
{
  return m_MotherBoard == aAnother.m_MotherBoard
    && m_vProcessors == aAnother.m_vProcessors
    && m_vHardDrives == aAnother.m_vHardDrives;
}