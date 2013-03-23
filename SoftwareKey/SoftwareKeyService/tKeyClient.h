#pragma once
#include "../SChannel/tInstanceIdentifier.h"

typedef void* HANDLE;
namespace boost { class thread; }
class ISocket;
class TSoftwareKey;
class ISecurityChannel;
class ISecurityChannelStream;

class TKeyClient
{
public:
  TKeyClient(
    const TSoftwareKey& aSoftwareKey,
    TStartsReferee& aStartsRef,
    ISocket& aSocketToBind);
  ~TKeyClient();

  int beginVerification();

  int kill();

  const TInstanceIdentifier& getInstId() const;

  void setCanStart();
  int waitToStart();

private:
  TKeyClient();
  TKeyClient(const TKeyClient&);

  static void clientSupportWork(TKeyClient* apThis);
  int clientSupportWork_impl();

  int commandDispatch(
    ISecurityChannel& aSecureChannel);
  int onReceiveInstId(
    ISecurityChannelStream& aStream,
    size_t aszSizeOfData);
  int onCrypt(
    ISecurityChannelStream& aStream,
    size_t aszSizeOfData,
    bool afEncrypt);

  // class Data
  const TSoftwareKey* m_pSoftwareKey;
  TStartsReferee* m_pStartsRef;
  ISocket* m_pSock;
  TInstanceIdentifier m_instId;

  HANDLE m_hCanBeStarted;
  HANDLE m_hNeedToStop;
  boost::thread* m_pSupportThread;
};