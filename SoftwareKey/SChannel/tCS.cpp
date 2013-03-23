#include <Windows.h>
#include "tCS.h"

TCS::TCS()
  :m_pCS(new CRITICAL_SECTION)
{
  ::InitializeCriticalSection(
    (CRITICAL_SECTION*)m_pCS);
}

TCS::~TCS()
{
  if(m_pCS)
  {
    ::DeleteCriticalSection(
      (CRITICAL_SECTION*)m_pCS);
    delete (CRITICAL_SECTION*)m_pCS;
    m_pCS = NULL;
  }
}

void TCS::lock()
{
  ::EnterCriticalSection(
    (CRITICAL_SECTION*)m_pCS);
}

void TCS::unlock()
{
  ::LeaveCriticalSection(
    (CRITICAL_SECTION*)m_pCS);
}

bool TCS::isLocked()
{
  if(::TryEnterCriticalSection((CRITICAL_SECTION*)m_pCS))
  {
    unlock();
    return false;
  }
  return true;
}

TCSLockGuard::TCSLockGuard(TCS& aCS)
  : m_pCS(&aCS)
{
  m_pCS->lock();
}

TCSLockGuard::~TCSLockGuard()
{
  m_pCS->unlock();
}