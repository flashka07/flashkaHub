#include "tInstanceIdentifier.h"

TInstanceIdentifier::TInstanceIdentifier()
  : m_dwProcessId(0)
{
}

TInstanceIdentifier::~TInstanceIdentifier()
{
}

bool TInstanceIdentifier::isEqual(
  const TInstanceIdentifier& aAnother) const
{
  return m_dwProcessId == aAnother.m_dwProcessId
    && m_processHashSum == aAnother.m_processHashSum
    && !m_strProcessName.compare(aAnother.m_strProcessName)
    && m_compId.isEqual(aAnother.m_compId);
}

const TComputerIdentifier& TInstanceIdentifier::getComputerId() const
{
  return m_compId;
}