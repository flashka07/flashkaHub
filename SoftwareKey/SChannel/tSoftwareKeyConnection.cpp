#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include <boost/thread.hpp>

#include "tSoftwareKeyConnection.h"
#include "iSoftwareKeyPingRP.h"
#include "tSoftwareKeyTask.h"
#include "tSoftwareKeyIds.h"

#include "iCertificate.h"
#include "iSocket.h"
#include "iSecurityChannel.h"
#include "iSecurityChannelStream.h"

#include "tInstanceIdentifier.h"

#include "iSchannelUtils.h"
#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"

TSoftwareKeyConnection::TSoftwareKeyConnection()
  : m_fIsConnected(false),
    m_fDisconnectedByClient(false),
    m_pCertificate(NULL),
    m_pPingRP(NULL),
    m_pSocket(NULL),
    m_pSecureChannel(NULL),
    m_pSCStream(NULL),
    m_hGotNewTask(NULL),
    m_hActivity(NULL),
    m_hNeedToStop(NULL),
    m_pPingerThread(NULL),
    m_pLog(IApcLog::getLog("TSoftwareKeyConnection"))
{
  m_hGotNewTask = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hGotNewTask)
  {
    int nResult = ::GetLastError();
    __L_BADH(m_pLog, "Error in ::CreateEvent", nResult);
    throw nResult;
  }

  m_hActivity = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hActivity)
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

TSoftwareKeyConnection::~TSoftwareKeyConnection()
{
  disconnect();

  if(m_pPingerThread)
  {
    delete m_pPingerThread;
    m_pPingerThread = NULL;
  }

  if(m_hNeedToStop)
    ::CloseHandle(m_hNeedToStop);

  if(m_hActivity)
    ::CloseHandle(m_hActivity);

  if(m_hGotNewTask)
    ::CloseHandle(m_hGotNewTask);

  cleanupChannel();
}

int TSoftwareKeyConnection::connect(
  const ICertificate& aCertToConnect,
  ISoftwareKeyPingRP& aCallBack)
{
  {
    TCSLockGuard lock(m_csStarted);
    if(m_fIsConnected)
    {
      __L_BAD(m_pLog, "Already connected to SoftwareKey");   
      return 0;
    }

    m_pCertificate = &aCertToConnect;
    m_pPingRP = &aCallBack;

    int nResult = setupChannel("localhost", "27015");
    if(nResult)
    {
      __L_BADH(m_pLog, "Cannot setupChannel", nResult);
      return nResult;
    }

    nResult = sendInstanceIdentifier();
    if(nResult)
    {
      __L_BADH(m_pLog, "Cannot sendInstanceIdentifier", nResult);
      return nResult;
    }

    // wait for answer
    std::string strIncomingCommand;
    size_t szReceive = 0;
    nResult = ISchannelUtils::receiveCommand(
      *m_pSCStream,
      strIncomingCommand,
      szReceive,
      c_unTimeoutInMs);
    if(nResult)
    {
      __L_BADH(m_pLog, "Cannot receive command", nResult);
      return nResult;
    }
  
    // if not is "canStart"
    if(c_strCmdCanStart.compare(strIncomingCommand))
    {
      __L_BAD(m_pLog, "Software key not found");
      return -31;
    }

    __L_TRK(m_pLog, "Software key was found");

    // connected sucessfully
    m_fIsConnected = true;
  }

  m_pPingerThread = new boost::thread(work, this);
  return 0;
}

int TSoftwareKeyConnection::disconnect()
{
  ::SetEvent(m_hNeedToStop);
  if(m_pPingerThread && m_pPingerThread->joinable())
    m_pPingerThread->join();
  return 0;
}

int TSoftwareKeyConnection::encryptData(
  const TBlob& aData,
  TBlob& aEncrypted)
{
  return pushTask(c_strCmdEncrypt, aData, aEncrypted);
}

int TSoftwareKeyConnection::decryptData(
  const TBlob& aEncrypted,
  TBlob& aData)
{
  return pushTask(c_strCmdDecrypt, aEncrypted, aData);
}

bool TSoftwareKeyConnection::isConnected(
  bool afCheckActivity) const
{
  bool fConnected = false;
  m_csStarted.lock();
  fConnected = m_fIsConnected;
  m_csStarted.unlock();

  // if we disconnected or not needed to
  // check activity, because it's may be long
  // (bounded by timeout)
  if(!fConnected || !afCheckActivity)
    return fConnected;

  // wait for activity event
  DWORD dwResult = ::WaitForSingleObject(
    m_hActivity, 
    c_unTimeoutInMs);
  if(dwResult == WAIT_OBJECT_0)
  {
    ::ResetEvent(m_hActivity);
    return true;
  }

  return false;
}

void TSoftwareKeyConnection::work(TSoftwareKeyConnection* apThis)
{
  int nResult = apThis->work_impl();
  if(nResult)
  {
    __L_BADH(apThis->m_pLog, "Error in work_impl", nResult);
    __L_BAD(apThis->m_pLog, ISchannelUtils::printError(nResult));
  }

  {
    TCSLockGuard lock(apThis->m_csStarted);
    apThis->m_fIsConnected = false;
  }

  if(!apThis->m_fDisconnectedByClient)
    apThis->m_pPingRP->onPingFail();
}

int TSoftwareKeyConnection::work_impl()
{
  // main communication loop
  int nResult = 0;
  while(true)
  {
    // wait for stop
    DWORD dwResult = ::WaitForSingleObject(
      m_hNeedToStop, 
      0);
    if(dwResult == WAIT_OBJECT_0)
    {
      __L_TRK(m_pLog, "Got request for stop. Stop dispatch...");
      m_fDisconnectedByClient = true;
      // send command to server
      nResult = ISchannelUtils::sendCommand(
        *m_pSCStream,
        c_strCmdShutdown,
        0);
      if(nResult)
      {
        __L_BADH(m_pLog, "Error while sending echo", nResult);
        // will not return error, just finish
      }
      return 0;
    }

    // show communication activity
    beActive();

    // look for task in queue
    TSoftwareKeyTask* pTask = NULL;
    {
      TCSLockGuard lock(m_csQueue);
      if(m_TaskQueue.size())
      {
        pTask = m_TaskQueue.front();
        m_TaskQueue.pop_front();
      }
    }

    // have a task for process?
    if(pTask)
    {
      nResult = processTask(*pTask);
      if(nResult)
      {
        __L_BADH(m_pLog, "Error while processTask", nResult);
        break;
      }
    }

    // send echo
    nResult = ISchannelUtils::sendCommand(
      *m_pSCStream,
      c_strCmdEcho,
      0);
    if(nResult)
    {
      __L_BADH(m_pLog, "Error while sending echo", nResult);
      break;
    }

    // receive anything
    std::string strIncomingCommand;
    size_t szReceive = 0;
    nResult = ISchannelUtils::receiveCommand(
      *m_pSCStream,
      strIncomingCommand,
      szReceive,
      c_unTimeoutInMs);
    if(nResult)
    {
      __L_BADH(m_pLog, "Cannot receive command", nResult);
      break;
    }

    // don't use all cpu time
    nResult = sleepABit();
    if(nResult)
    {
      __L_BADH(m_pLog, "Error in sleepABit", nResult);
      break;
    }

    // dispatch commands
    if(!c_strCmdEcho.compare(strIncomingCommand))
    {
      // echo
      continue;
    }
    else if(!c_strCmdShutdown.compare(strIncomingCommand))
    {
      // software key was shutted down
      __L_TRK(m_pLog, "> Software key was shutted down");
      break;
    }
    else
    {
      __L_BAD(m_pLog, "Wrong incoming command");
      nResult = -35;
      break;
    }

    // show communication activity
    beActive();
  }

  return nResult;
}

int TSoftwareKeyConnection::processTask(
  TSoftwareKeyTask& aTask)
{
  int nResult = ISchannelUtils::sendCommand(
    *m_pSCStream,
    aTask.getCommand(),
    aTask.getSource().size());
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while sendCommand", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::sendData(
    *m_pSCStream,
    aTask.getSource());
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while sendData", nResult);
    return nResult;
  }

  // one iteration cycle
  while(true)
  {
    // wait for answer
    std::string strIncomingCommand;
    size_t szReceive = 0;
    nResult = ISchannelUtils::receiveCommand(
      *m_pSCStream,
      strIncomingCommand,
      szReceive,
      c_unTimeoutInMs);
    if(nResult)
    {
      __L_BADH(m_pLog, "Cannot receive command", nResult);
      break;
    }

    // do not work in multithread env without identifiers of
    // tasks
    if(aTask.getCommand().compare(strIncomingCommand))
    {
      __L_BAD(m_pLog, "Wrong incoming command");
      nResult = -35;
      break;
    }

    // get result data
    aTask.getResultBuffer().resize(szReceive);
    nResult = ISchannelUtils::receiveData(
      *m_pSCStream,
      aTask.getResultBuffer(),
      c_unTimeoutInMs);
    if(nResult)
    {
      __L_BADH(m_pLog, "Cannot receive result data", nResult);
    }

    break;
  }

  aTask.setCompleted(nResult);
  return nResult;
}

int TSoftwareKeyConnection::pushTask(
  const std::string& astrCommand,
  const TBlob& aSource,
  TBlob& aResult)
{
  m_csQueue.lock();

  std::auto_ptr<TSoftwareKeyTask> spTask(
    new TSoftwareKeyTask(
      astrCommand,
      aSource,
      aResult));

  m_TaskQueue.push_back(spTask.get());

  m_csQueue.unlock();

  ::SetEvent(m_hGotNewTask);

  // now wait till task finished
  int nTaskResult = 0;
  int nResult = spTask->waitForComplete(nTaskResult);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while spTask->waitForComplete", nResult);
    return nResult;
  }

  if(nTaskResult)
  {
    __L_BADH(m_pLog, "Eror being while task processing", nTaskResult);
  }
  return nTaskResult;
}

int TSoftwareKeyConnection::setupChannel(
  const std::string& astrAddress,
  const std::string& astrPort)
{
  m_pSocket = ISocket::create();
  if(!m_pSocket)
  {
    __L_EXC(m_pLog, "Cannot create Socket");
    return -5;
  }

  int nResult = m_pSocket->connect(
    astrAddress,
    astrPort);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot connect to Softwarekey socket", nResult);
    return nResult;
  }

  m_pSecureChannel = ISecurityChannel::create();
  if(!m_pSecureChannel)
  {
    __L_EXC(m_pLog, "Cannot create Secure Channel");
    return -5;
  }

  nResult = m_pSecureChannel->authenticate(
    *m_pSocket,
    *m_pCertificate);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot auth Softwarekey socket", nResult);
    return nResult;
  }

  m_pSCStream = ISecurityChannelStream::create();
  if(!m_pSCStream)
  {
    __L_EXC(m_pLog, "Cannot create Secure Channel stream");
    return -5;
  }

  nResult = m_pSCStream->attach(*m_pSecureChannel);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot attach to Secure Channel", nResult);
    return nResult;
  }

  return 0;
}

void TSoftwareKeyConnection::cleanupChannel()
{
  if(m_pSCStream)
  {
    delete m_pSCStream;
    m_pSCStream = NULL;
  }
  if(m_pSecureChannel)
  {
    delete m_pSecureChannel;
    m_pSecureChannel = NULL;
  }
  if(m_pSocket)
  {
    delete m_pSocket;
    m_pSocket = NULL;
  }
}

int TSoftwareKeyConnection::sendInstanceIdentifier()
{
  TInstanceIdentifier instId;
  int nResult = ISchannelUtils::generateInstanceID(instId);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot generateInstanceID", nResult);
    return nResult;
  }
  
  TBlob vSerialized;
  nResult = ISchannelUtils::serializeInstanceId(
    instId,
    vSerialized);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot serializeInstanceId", nResult);
    return nResult;
  }

  // send cmd to recieve id
  nResult = ISchannelUtils::sendCommand(
    *m_pSCStream,
    c_strCmdRcvInstId,
    vSerialized.size());
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot send cmd", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::sendData(
    *m_pSCStream,
    vSerialized);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot send identificator", nResult);
    return nResult;
  }

  return 0;
}

void TSoftwareKeyConnection::beActive()
{
  ::SetEvent(m_hActivity);
}

int TSoftwareKeyConnection::sleepABit()
{
  unsigned int unTimeToWait = c_unTimeoutInMs / 2;
  unsigned int unSleepAtOnce = unTimeToWait / 5;
  unsigned int unSleepsCount = 5;
  while(unSleepsCount--)
  {
    DWORD dwResult = ::WaitForSingleObject(
      m_hGotNewTask,
      0);
    if(dwResult == WAIT_OBJECT_0)
    {
      ::ResetEvent(m_hGotNewTask);
      break;
    }
    ::Sleep(unSleepAtOnce);
  }

  return 0;
}