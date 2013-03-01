#pragma once
#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include <vector>

#include "iSchannelSessionServer.h"

const DWORD c_dwAllowedProtocols = SP_PROT_TLS1_2;

class ISocketStream;

class TSchannelSessionServer : public ISchannelSessionServer
{
public:
  TSchannelSessionServer();
  ~TSchannelSessionServer();

  int authenticate(
    ISocket& aSocket,
    const ICertificate& aCertificate);
  int renegotiate();
  int shutdown(
    bool afSendNotification);

  CredHandle& getCreditionals();
  SecHandle& getContext();

  bool isEstablished() const;

  ISocket* getAttachedSocket();
  size_t getExtraDataSize() const;
  size_t getExtraData(void* apBuffer) const;

private:
  int acquireCredentials(
    const ICertificate& aCertificate);

  int authenticateOnStream(
    ISocketStream& aSockStream,
    std::vector<BYTE>& avExtraData);

  void freeContextBuff(
    SecBufferDesc& aBuffDesc);

  void freeInnerResources();

  // class data
  CredHandle m_hCred;
  SecHandle  m_hContext;
  unsigned long m_ulContextAttribs;
  DWORD m_dwCredFlags;

  bool m_fEstablished;

  const ICertificate* m_pCertificate;
  ISocket* m_pSocket;

  std::vector<BYTE> m_vExtraData;
};