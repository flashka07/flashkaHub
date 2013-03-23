#include <Windows.h>
#include "tSoftwareKeyTask.h"

#include "iLog.h"

TSoftwareKeyTask::TSoftwareKeyTask(
  const std::string& astrCommand,
  const TBlob& aData,
  TBlob& aResult)
  : m_strCommand(astrCommand),
    m_SourceData(aData),
    m_ResultData(aResult),
    m_nCompleteResult(0),
    m_hComplete(NULL)
{
  m_hComplete = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hComplete)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CreateEvent", nResult);
    throw nResult;
  }
}

TSoftwareKeyTask::~TSoftwareKeyTask()
{
  if(m_hComplete)
    ::CloseHandle(m_hComplete);
}

int TSoftwareKeyTask::waitForComplete(
  int& anCompleteResult,
  unsigned int aunTimeout)
{
  DWORD dwResult = ::WaitForSingleObject(
    m_hComplete, 
    aunTimeout);
  if(dwResult == WAIT_OBJECT_0)
  {
    anCompleteResult = m_nCompleteResult;
    return 0;
  }
  else
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::WaitForSingleObject", nResult);
    anCompleteResult = 0;
    return nResult;
  }
}

void TSoftwareKeyTask::setCompleted(
  int anResultCode)
{
  m_nCompleteResult = anResultCode;
  ::SetEvent(m_hComplete);
}

const std::string& TSoftwareKeyTask::getCommand() const
{
  return m_strCommand;
}

const TBlob& TSoftwareKeyTask::getSource() const
{
  return m_SourceData;
}

TBlob& TSoftwareKeyTask::getResultBuffer()
{
  return m_ResultData;
}