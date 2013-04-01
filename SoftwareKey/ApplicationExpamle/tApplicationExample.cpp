#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>
#include <iostream>
#include <string>
#include "tApplicationExample.h"

#include "../SChannel/iSoftwareKeyConnection.h"
#include "../SChannel/iCertificate.h"

#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"
#include "../SChannel/iLog.h"

TApplicationExample::TApplicationExample()
  : m_pKey(ISoftwareKeyConnection::createInstance()),
    m_pCert(ICertificate::createInstance()),
    m_pLog(IApcLog::getLog("TApplicationExample"))
{
}

TApplicationExample::~TApplicationExample()
{
  cleanup();
}

int TApplicationExample::work()
{
  ILog("Trying to connect to Software Key...");
  int nResult = m_pKey->connect(
    *m_pCert,
    *this);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot connect to Software Key", nResult);
    return nResult;
  }

  ILog("> Connected to Software Key");

  ILog("===To stop enter \"exit\" command===");
  std::string strInput;
  while(strInput.compare("exit"))
  {
    std::cin >> strInput;
    __L_BAD(m_pLog, strInput + " passed");
  }

  ILog("> Finishing...");
  return 0;
}

void TApplicationExample::onPingFail()
{
  // close application when connection lost
  ILog("Ping Software Key failed! Aborting");
  cleanup();
  std::exit(0);
}

void TApplicationExample::cleanup()
{
  if(m_pKey)
  {
    delete m_pKey;
    m_pKey = NULL;
  }
  if(m_pCert)
  {
    delete m_pCert;
    m_pCert = NULL;
  }
}