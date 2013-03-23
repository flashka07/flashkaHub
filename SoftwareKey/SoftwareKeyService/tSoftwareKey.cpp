#include <Windows.h>
#include <memory>
#include <boost/thread.hpp>

#include "tSoftwareKey.h"
#include "tKeyClient.h"
#include "tStartsReferee.h"

#include "../SChannel/iSocket.h"
#include "../SChannel/iCertificate.h"
#include "../SChannel/tCryptProv.h"
#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/tCS.h"
#include "../SChannel/iLog.h"

TCS g_csfStarted;

const size_t c_szKeyLength = 32;
const BYTE c_Key[c_szKeyLength] = 
{
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

TSoftwareKey::TSoftwareKey()
  : m_fStarted(false),
    m_hStartEvent(NULL),
    m_hStopEvent(NULL),
    m_pCert(ICertificate::createInstance()),
    m_pCryptProv(new TCryptProv(L"aesprov")),
    m_hAesKey(NULL),
    m_pNetListenThread(NULL),
    m_pStartsRef(new TStartsReferee)
{
  m_hStartEvent = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hStartEvent)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CreateEvent", nResult);
    throw nResult;
  }

  m_hStopEvent = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hStopEvent)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CreateEvent", nResult);
    throw nResult;
  }
}

TSoftwareKey::~TSoftwareKey()
{
  stop();

  if(m_pNetListenThread)
  {
    delete m_pNetListenThread;
    m_pNetListenThread = NULL;
  }

  if(m_pStartsRef)
  {
    delete m_pStartsRef;
    m_pStartsRef = NULL;
  }  

  if(m_hStartEvent)
    ::CloseHandle(m_hStartEvent);

  if(m_hStopEvent)
    ::CloseHandle(m_hStopEvent);

  if(m_pCert)
  {
    delete m_pCert;
    m_pCert = NULL;
  }

  if(m_hAesKey)
  {
    ::CryptDestroyKey(m_hAesKey);
    m_hAesKey = NULL;
  }

  if(m_pCryptProv)
  {
    delete m_pCryptProv;
    m_pCryptProv = NULL;
  }
}

int TSoftwareKey::start()
{
  if(isRunning())
    return 0;
  int nResult = init();
  if(nResult)
  {
    ILogR("Error in init", nResult);
    return nResult;
  }
  // say that we starting
  ::SetEvent(m_hStartEvent);
  return 0;
}

int TSoftwareKey::stop()
{
  if(!isRunning())
    return 0;

  {
    TCSLockGuard lock(g_csfStarted);
    m_fStarted = false;
  }

  int nResult = m_pStartsRef->shutdownAll();
  if(nResult)
  {
    ILogR("Cannot shutdown StartsRef", nResult);
  }

  m_pNetListenThread->join();

  return 0;
}

bool TSoftwareKey::isRunning() const
{
  TCSLockGuard lock(g_csfStarted);
  return m_fStarted;
}

int TSoftwareKey::waitForStop(
  unsigned int aunTimeout,
  bool& afStopped)
{
  afStopped = false;

  DWORD dwResult = ::WaitForSingleObject(
    m_hStopEvent, 
    aunTimeout);
  if(dwResult == WAIT_OBJECT_0)
  {
    afStopped = true;
  }

  return dwResult;
}

const ICertificate& TSoftwareKey::getCertificate() const
{
  return *m_pCert;
}

HCRYPTKEY TSoftwareKey::getAESKey() const
{
  return m_hAesKey;
}

int TSoftwareKey::init()
{
  m_pNetListenThread = new boost::thread(listenerWork, this);

  // TODO: Certificate load
  // load AES Key
  TBlob vKeyBlob(c_Key, c_Key + c_szKeyLength);
  int nResult = ISchannelUtils::importAES256Key(
    *m_pCryptProv,
    vKeyBlob,
    m_hAesKey);
  if(nResult)
  {
    ILogR("Error in importAES256Key", nResult);
    return nResult;
  }
  return 0;
}

void TSoftwareKey::listenerWork(TSoftwareKey* apThis)
{
  int nResult = apThis->listenerWork_impl();
  if(nResult)
  {
    ILogR("Error in listenerWork_impl", nResult);
    ISchannelUtils::printError(nResult);
  }

  // say that we stop
  ::SetEvent(apThis->m_hStopEvent);
}

int TSoftwareKey::listenerWork_impl()
{
  // wait for start
  DWORD dwResult = ::WaitForSingleObject(
    m_hStartEvent, 
    INFINITE);
  if(dwResult == WAIT_OBJECT_0)
  {
    // starting
    TCSLockGuard lock(g_csfStarted);
    m_fStarted = true;
  }
  else
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::WaitForSingleObject", nResult);
    return nResult;
  }
  
  // open softwarekey port
  std::auto_ptr<ISocket> spSrvSocket(ISocket::create());
  if(!spSrvSocket.get())
  {
    ILog("Cannot create Server Socket");
    return -5;
  }

  int nResult = spSrvSocket->listen(
    ISocket::maxConnectionQueue(),
    c_strListenPort,
    c_strListenAddress);
  if(nResult)
  {
    ILogR("Error in spSrvSocket->listen", nResult);
    return nResult;
  }

  // accept clients
  while(isRunning())
  {
    ILog("Trying to accept...");
    std::auto_ptr<ISocket> spIncSocket(ISocket::create());
    if(!spIncSocket.get())
    {
      ILog("Cannot create Incoming");
      return -5;
    }
    nResult = spSrvSocket->accept(
      c_unAcceptTimeoutMs,
      *spIncSocket);
    if(nResult)
    {
      ILogR("Error in spSrvSocket->accept", nResult);
      return nResult;
    }
    if(!spIncSocket->isEstablished())
      continue;

    int nResult = m_pStartsRef->tryStart(
      *this, *spIncSocket.release());
    if(nResult)
    {
      ILogR("Error in spSrvSocket->accept", nResult);
      return nResult;
    }
  }

  return 0;
}