#pragma once
#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "iSecurityChannel.h"
#include "tBlob.h"

const DWORD c_dwAllowedProtocols = SP_PROT_TLS1_2;
const DWORD c_dwServerCredFlags = 
  SCH_CRED_NO_SYSTEM_MAPPER;
const DWORD c_dwServerContextAttr = 
  ASC_REQ_CONFIDENTIALITY |
  ASC_REQ_REPLAY_DETECT |
  ASC_REQ_STREAM |
  ASC_REQ_MUTUAL_AUTH;
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

class TSecurityChannel : public ISecurityChannel
{
public:
  TSecurityChannel();
  ~TSecurityChannel();

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

  int shutdown_impl(
    bool afSendNotification);

  void freeContextBuff(
    SecBufferDesc& aBuffDesc);

  void freeInnerResources();

  void setMode(
    bool afServerMode);

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