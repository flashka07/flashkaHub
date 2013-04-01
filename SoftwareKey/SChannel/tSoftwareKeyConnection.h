#pragma once
#include <string>
#include <list>
#include "iSoftwareKeyConnection.h"
#include "tCS.h"

typedef void* HANDLE;
namespace boost { class thread; }
class ISocket;
class ISecurityChannel;
class ISecurityChannelStream;
class ISoftwareKeyPingRP;
class TSoftwareKeyTask;
class IApcLog;

typedef std::list<TSoftwareKeyTask*> TSKTaksQueue;

class TSoftwareKeyConnection : public ISoftwareKeyConnection
{
public:
  TSoftwareKeyConnection();
  ~TSoftwareKeyConnection();

  int connect(
    const ICertificate& aCertToConnect,
    ISoftwareKeyPingRP& aCallBack);

  int disconnect();

  int encryptData(
    const TBlob& aData,
    TBlob& aEncrypted);

  int decryptData(
    const TBlob& aEncrypted,
    TBlob& aData);

  bool isConnected(
    bool afCheckActivity) const;

private:
  static void work(TSoftwareKeyConnection* apThis);
  int work_impl();

  int processTask(
    TSoftwareKeyTask& aTask);

  int pushTask(
    const std::string& astrCommand,
    const TBlob& aSource,
    TBlob& aResult);

  int setupChannel(
    const std::string& astrAddress,
    const std::string& astrPort);

  void cleanupChannel();

  int sendInstanceIdentifier();

  void beActive();

  int sleepABit();

  // class data
  bool m_fIsConnected;
  bool m_fDisconnectedByClient;
  
  const ICertificate* m_pCertificate;
  ISoftwareKeyPingRP* m_pPingRP;

  ISocket* m_pSocket;
  ISecurityChannel* m_pSecureChannel;
  ISecurityChannelStream* m_pSCStream;

  TSKTaksQueue m_TaskQueue;
  TCS m_csQueue;
  HANDLE m_hGotNewTask;

  mutable TCS m_csStarted;
  HANDLE m_hActivity;
  HANDLE m_hNeedToStop;
  boost::thread* m_pPingerThread;

  IApcLog* m_pLog;
};