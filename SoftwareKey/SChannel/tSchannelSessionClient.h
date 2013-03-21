#pragma once
#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "iSchannelSessionClient.h"
#include "tBlob.h"

const DWORD c_dwClientAllowedProtocols = SP_PROT_TLS1_2;
const DWORD c_dwClientCredFlags = 
  SCH_CRED_MANUAL_CRED_VALIDATION;
const DWORD c_dwClientContextAttr = 
  ISC_REQ_CONFIDENTIALITY |
  ISC_REQ_INTEGRITY |
  ISC_REQ_REPLAY_DETECT |
  ISC_REQ_STREAM |
  ISC_REQ_USE_SUPPLIED_CREDS |
  ISC_REQ_MANUAL_CRED_VALIDATION;

class ISocketStream;

class TSchannelSessionClient : public ISchannelSessionClient
{
public:
  TSchannelSessionClient();
  ~TSchannelSessionClient();

  int authenticate(
    ISocket& aSocket,
    const ICertificate& aCertificate,
    bool afServerMode);
  int renegotiate();
  int shutdown(
    bool afSendNotification);

  CredHandle& getCreditionals();
  SecHandle& getContext();

  bool isInServerMode() const;
  bool isEstablished() const;

  ISocket* getAttachedSocket();
  size_t getExtraDataSize() const;
  size_t getExtraData(void* apBuffer) const;

private:
  int acquireCredentials(
    const ICertificate& aCertificate);

  int authenticateOnStream(
    ISocketStream& aSockStream,
    TBlob& avExtraData);

  void freeContextBuff(
    SecBufferDesc& aBuffDesc);

  void freeInnerResources();

  // class data
  bool m_fServerMode;

  CredHandle m_hCred;
  SecHandle  m_hContext;
  unsigned long m_ulContextAttribs;
  DWORD m_dwCredFlags;

  bool m_fEstablished;

  const ICertificate* m_pCertificate;
  ISocket* m_pSocket;

  TBlob m_vExtraData;
};