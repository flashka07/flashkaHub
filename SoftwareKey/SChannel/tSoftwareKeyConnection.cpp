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
#include "iLog.h"

TSoftwareKeyConnection::TSoftwareKeyConnection()
  : m_fIsConnected(false),
    m_fDisconnectedByClient(false),
    m_pCertificate(NULL),
    m_pPingRP(NULL),
    m_pSocket(NULL),
    m_pSecureChannel(NULL),
    m_pSCStream(NULL),
    m_hActivity(NULL),
    m_hNeedToStop(NULL),
    m_pPingerThread(NULL)
{
  m_hActivity = ::CreateEvent( 
    NULL,
    FALSE, // is auto-reset
    FALSE,
    NULL);
  if(!m_hActivity)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CreateEvent", nResult);
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
    ILogR("Error in ::CreateEvent", nResult);
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
      ILog("Already connected to SoftwareKey");   
      return 0;
    }

    m_pCertificate = &aCertToConnect;
    m_pPingRP = &aCallBack;

    int nResult = setupChannel("localhost", "27015");
    if(nResult)
    {
      ILogR("Cannot setupChannel", nResult);
      return nResult;
    }

    nResult = sendInstanceIdentifier();
    if(nResult)
    {
      ILogR("Cannot sendInstanceIdentifier", nResult);
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
      ILogR("Cannot receive command", nResult);
      return nResult;
    }
  
    // if not is "canStart"
    if(c_strCmdCanStart.compare(strIncomingCommand))
    {
      ILog("Software key not found");
      return -31;
    }

    ILog("Software key was found");

    // connected sucessfully
    m_fIsConnected = true;
  }

  m_pPingerThread = new boost::thread(work, this);
  return 0;
}

int TSoftwareKeyConnection::disconnect()
{
  ::SetEvent(m_hNeedToStop);
  if(m_pPingerThread->joinable())
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
    ILogR("Error in work_impl", nResult);
    ISchannelUtils::printError(nResult);
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
      ILog("Got request for stop. Stop dispatch...");
      m_fDisconnectedByClient = true;
      // send command to server
      nResult = ISchannelUtils::sendCommand(
        *m_pSCStream,
        c_strCmdShutdown,
        0);
      if(nResult)
      {
        ILogR("Error while sending echo", nResult);
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
        ILogR("Error while processTask", nResult);
        break;
      }
    }
    else
    {
      // send echo
      nResult = ISchannelUtils::sendCommand(
        *m_pSCStream,
        c_strCmdEcho,
        0);
      if(nResult)
      {
        ILogR("Error while sending echo", nResult);
        break;
      }
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
      ILogR("Cannot receive command", nResult);
      break;
    }

    if(!c_strCmdEcho.compare(strIncomingCommand))
    {
      // echo
      continue;
    }
    else if(!c_strCmdShutdown.compare(strIncomingCommand))
    {
      // software key was shutted down
      ILog("> Software key was shutted down");
      break;
    }
    else
    {
      ILog("Wrong incoming command");
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
    ILogR("Error while sendCommand", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::sendData(
    *m_pSCStream,
    aTask.getSource());
  if(nResult)
  {
    ILogR("Error while sendData", nResult);
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
      ILogR("Cannot receive command", nResult);
      break;
    }

    // do not work in multithread env without identifiers of
    // tasks
    if(aTask.getCommand().compare(strIncomingCommand))
    {
      ILog("Wrong incoming command");
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
      ILogR("Cannot receive result data", nResult);
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

  // now wait till task finished
  int nTaskResult = 0;
  int nResult = spTask->waitForComplete(nTaskResult);
  if(nResult)
  {
    ILogR("Error while spTask->waitForComplete", nResult);
    return nResult;
  }

  if(nTaskResult)
  {
    ILogR("Eror being while task processing", nTaskResult);
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
    ILog("Cannot create Socket");
    return -5;
  }

  int nResult = m_pSocket->connect(
    astrAddress,
    astrPort);
  if(nResult)
  {
    ILogR("Cannot connect to Softwarekey socket", nResult);
    return nResult;
  }

  m_pSecureChannel = ISecurityChannel::create();
  if(!m_pSecureChannel)
  {
    ILog("Cannot create Secure Channel");
    return -5;
  }

  nResult = m_pSecureChannel->authenticate(
    *m_pSocket,
    *m_pCertificate);
  if(nResult)
  {
    ILogR("Cannot auth Softwarekey socket", nResult);
    return nResult;
  }

  m_pSCStream = ISecurityChannelStream::create();
  if(!m_pSCStream)
  {
    ILog("Cannot create Secure Channel stream");
    return -5;
  }

  nResult = m_pSCStream->attach(*m_pSecureChannel);
  if(nResult)
  {
    ILogR("Cannot attach to Secure Channel", nResult);
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
    ILogR("Cannot generateInstanceID", nResult);
    return nResult;
  }
  
  TBlob vSerialized;
  nResult = ISchannelUtils::serializeInstanceId(
    instId,
    vSerialized);
  if(nResult)
  {
    ILogR("Cannot serializeInstanceId", nResult);
    return nResult;
  }

  // send cmd to recieve id
  nResult = ISchannelUtils::sendCommand(
    *m_pSCStream,
    c_strCmdRcvInstId,
    vSerialized.size());
  if(nResult)
  {
    ILogR("Cannot send cmd", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::sendData(
    *m_pSCStream,
    vSerialized);
  if(nResult)
  {
    ILogR("Cannot send identificator", nResult);
    return nResult;
  }

  return 0;
}

void TSoftwareKeyConnection::beActive()
{
  ::SetEvent(m_hActivity);
}