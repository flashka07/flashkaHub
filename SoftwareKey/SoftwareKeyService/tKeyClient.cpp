#include <memory>
#include <boost/thread.hpp>

#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "tKeyClient.h"
#include "tSoftwareKey.h"
#include "tStartsReferee.h"

#include "../SChannel/tSoftwareKeyIds.h"

#include "../SChannel/iSocket.h"
#include "../SChannel/iCertificate.h"
#include "../SChannel/iSecurityChannel.h"
#include "../SChannel/iSecurityChannelStream.h"

#include "../SChannel/iSchannelUtils.h"
#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"

TKeyClient::TKeyClient(
  const TSoftwareKey& aSoftwareKey,
  TStartsReferee& aStartsRef,
  ISocket& aSocketToBind)
  : m_pSoftwareKey(&aSoftwareKey),
    m_pStartsRef(&aStartsRef),
    m_pSock(&aSocketToBind),
    m_hCanBeStarted(NULL),
    m_hNeedToStop(NULL),
    m_pSupportThread(NULL),
    m_pLog(IApcLog::getLog("TKeyClient"))
{
  m_hCanBeStarted = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hCanBeStarted)
  {
    int nResult = ::GetLastError();
    __L_BADH(m_pLog, "Error in ::CreateEvent", nResult);
    throw nResult;
  }

  m_hNeedToStop = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hNeedToStop)
  {
    int nResult = ::GetLastError();
    __L_BADH(m_pLog, "Error in ::CreateEvent", nResult);
    throw nResult;
  }
}

TKeyClient::~TKeyClient()
{
  if(m_pSupportThread)
  {
    delete m_pSupportThread;
    m_pSupportThread = NULL;
  }

  if(m_pSock)
  {
    delete m_pSock;
    m_pSock = NULL;
  }

  if(m_hCanBeStarted)
    ::CloseHandle(m_hCanBeStarted);

  if(m_hNeedToStop)
    ::CloseHandle(m_hNeedToStop);
}

TKeyClient::TKeyClient()
{
}

TKeyClient::TKeyClient(const TKeyClient&)
{
}

int TKeyClient::beginVerification()
{
  if(m_pSupportThread)
    return 0;

  m_pSupportThread = new boost::thread(clientSupportWork, this);
  return 0;
}

int TKeyClient::kill()
{
  // need to backup pointer to thread,
  // because when m_pSupportThread is finished,
  // it would be deleted by destructor
  boost::thread* pWorkThread = m_pSupportThread;
  m_pSupportThread = NULL;
  ::SetEvent(m_hNeedToStop);
  if(pWorkThread->joinable())
    pWorkThread->join();

  delete pWorkThread;
  return 0;
}

const TInstanceIdentifier& TKeyClient::getInstId() const
{
  return m_instId;
}

void TKeyClient::setCanStart()
{
  ::SetEvent(m_hCanBeStarted);
}

int TKeyClient::waitToStart()
{
  DWORD dwResult = ::WaitForSingleObject(
    m_hCanBeStarted, 
    INFINITE);
  if(dwResult == WAIT_OBJECT_0)
  {
    return 0;
  }
  else
  {
    int nResult = ::GetLastError();
    __L_BADH(m_pLog, "Error in ::WaitForSingleObject", nResult);
    return nResult;
  }
}

void TKeyClient::clientSupportWork(TKeyClient* apThis)
{
  int nResult = apThis->clientSupportWork_impl();
  if(nResult)
  {
    __L_BADH(apThis->m_pLog, "Error in clientSupportWork_impl", nResult);
    __L_BAD(apThis->m_pLog, ISchannelUtils::printError(nResult));
  }

  // delete this
  apThis->m_pStartsRef->forgive(*apThis, true);
}

int TKeyClient::clientSupportWork_impl()
{
  std::auto_ptr<ISecurityChannel> spSecurityChannel(
    ISecurityChannel::create());
  if(!spSecurityChannel.get())
  {
    __L_EXC(m_pLog, "Cannot create ISecurityChannel");
    return -5;
  }

  int nResult = spSecurityChannel->authenticate(
    *m_pSock,
    m_pSoftwareKey->getCertificate(),
    true);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot set SecurityChannel with client", nResult);
    return nResult;
  }

  __L_TRK(m_pLog, "> Security channel was set");

  nResult = commandDispatch(
    *spSecurityChannel);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in commandDispatch", nResult);
    return nResult;
  }

  return 0;
}

int TKeyClient::commandDispatch(
  ISecurityChannel& aSecureChannel)
{
  std::auto_ptr<ISecurityChannelStream> spSCStream(
    ISecurityChannelStream::create());
  if(!spSCStream.get())
  {
    __L_EXC(m_pLog, "Cannot create ISecurityChannelStream");
    return -5;
  }

  int nResult = spSCStream->attach(aSecureChannel);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot attach ISecurityChannelStream", nResult);
    return nResult;
  }

  while(true)
  {
    // wait to stop
    bool fNeedToStop = false;
    DWORD dwResult = ::WaitForSingleObject(
      m_hNeedToStop, 
      0);
    if(dwResult == WAIT_OBJECT_0)
    {
      __L_TRK(m_pLog, "Got request for stop. Stop dispatch...");
      fNeedToStop = true;
    }

    // receive command
    __L_TRK(m_pLog, "Waiting for command...");

    std::string strIncomingCmd;
    size_t szSizeOfData = 0;
    nResult = ISchannelUtils::receiveCommand(
      *spSCStream,
      strIncomingCmd,
      szSizeOfData,
      c_unTimeoutInMs);
    if(nResult)
    {
      __L_BADH(m_pLog, "Cannot receiveCommand", nResult);
      return nResult;
    }

    // stop anyway if needed
    if(fNeedToStop)
    {
      // notify key-client with shutdown command
      nResult = ISchannelUtils::sendCommand(
        *spSCStream,
        c_strCmdShutdown,
        0);
      break;
    }

    __L_TRK(m_pLog, "Got command " + strIncomingCmd);
    if(!c_strCmdEcho.compare(strIncomingCmd))
    {
      nResult = ISchannelUtils::sendCommand(
        *spSCStream,
        c_strCmdEcho,
        0);
      //::Sleep(c_unTimeoutInMs / 2);
    }
    else if(!c_strCmdRcvInstId.compare(strIncomingCmd))
    {
      nResult = onReceiveInstId(
        *spSCStream,
        szSizeOfData);
    }
    else if(!c_strCmdShutdown.compare(strIncomingCmd))
    {
      // client has disconnected
      __L_TRK(m_pLog, "Client has Disconnected");
      break;
    }
    else if(!c_strCmdEncrypt.compare(strIncomingCmd))
    {
      nResult = onCrypt(
        *spSCStream,
        szSizeOfData,
        true);
    }
    else if(!c_strCmdDecrypt.compare(strIncomingCmd))
    {
      nResult = onCrypt(
        *spSCStream,
        szSizeOfData,
        false);
    }
    else
    {
      __L_BAD(m_pLog, "Unknown command " + strIncomingCmd);
      return -35;
    }

    // check for errors
    if(nResult)
    {
      __L_BADH(m_pLog, "Error while handling command " + strIncomingCmd, nResult); 
      return nResult;
    }
  }

  return nResult;
}

int TKeyClient::onReceiveInstId(
  ISecurityChannelStream& aStream,
  size_t aszSizeOfData)
{
  TBlob vSerializedId(aszSizeOfData);
  int nResult = ISchannelUtils::receiveData(
    aStream,
    vSerializedId,
    c_unTimeoutInMs);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot receive InstId", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::restoreInstanceId(
    vSerializedId,
    m_instId);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot restore InstId", nResult);
    return nResult;
  }

  bool fCanStart = false;
  nResult = m_pStartsRef->isAbleToStart(
    *this,
    fCanStart);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in isAbleToStart", nResult);
    return nResult;
  }

  if(!fCanStart)
  {
    __L_TRK(m_pLog, "Access to start is denied");
  }
  else
  {
    __L_TRK(m_pLog, "Application can start");
  }
  nResult = ISchannelUtils::sendCommand(
    aStream,
    fCanStart ? c_strCmdCanStart : c_strCmdCannotStart,
    0);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot send command", nResult);
    return nResult;
  }

  return 0;
}

int TKeyClient::onCrypt(
  ISecurityChannelStream& aStream,
  size_t aszSizeOfData,
  bool afEncrypt)
{
  TBlob vIncomingData(aszSizeOfData);
  int nResult = ISchannelUtils::receiveData(
    aStream,
    vIncomingData,
    c_unTimeoutInMs);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot receive data", nResult);
    return nResult;
  }

  TBlob vResult;
  if(afEncrypt)
  {
    nResult = ISchannelUtils::encryptAES256(
      m_pSoftwareKey->getAESKey(),
      vIncomingData,
      vResult);
  }
  else
  {
    nResult = ISchannelUtils::decryptAES256(
      m_pSoftwareKey->getAESKey(),
      vIncomingData,
      vResult);
  }
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while crypt operation", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::sendCommand(
    aStream,
    afEncrypt ? c_strCmdEncrypt : c_strCmdDecrypt,
    vResult.size());
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot send command", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::sendData(aStream, vResult);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot send result", nResult);
    return nResult;
  }
  return 0;
}