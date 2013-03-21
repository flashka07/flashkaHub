#include "tSchannelSessionClient.h"

#include "iSocketStream.h"
#include "iCertificate.h"
#include "iSchannelUtils.h"
#include "iLog.h"

TSchannelSessionClient::TSchannelSessionClient()
  : m_fServerMode(false),
    m_ulContextAttribs(c_dwClientContextAttr),
    m_dwCredFlags(c_dwClientCredFlags),
    m_fEstablished(false),
    m_pCertificate(NULL),
    m_pSocket(NULL)
{
  ::memset(&m_hCred, 0, sizeof(m_hCred));
  ::memset(&m_hContext, 0, sizeof(m_hContext));
}

TSchannelSessionClient::~TSchannelSessionClient()
{
  shutdown(false);
}

int TSchannelSessionClient::authenticate(
  ISocket& aSocket,
  const ICertificate& aCertificate,
  bool afServerMode)
{
  shutdown(false);

  m_pCertificate = &aCertificate;
  m_pSocket = &aSocket;

  int nResult = acquireCredentials(aCertificate);
  if(nResult)
  {
    ILogR("Error in acquireCredentials", nResult);
    return nResult;
  }

  std::auto_ptr<ISocketStream> spStream(
    ISocketStream::create());
  if(!spStream.get())
  {
    ILog("!!! Cannot create ISocketStream");
    return -3;
  }
  nResult = spStream->attach(*m_pSocket);
  if(nResult)
  {
    ILogR("Error in attach to socket", nResult);
    return nResult;
  }
  nResult = authenticateOnStream(
    *spStream,
    m_vExtraData);
  if(nResult)
  {
    ILogR("Error in authenticateOnStream", nResult);
    return nResult;
  }
  m_fEstablished = true;
  ILog("> Authentication succeed");

  return 0;
}

int TSchannelSessionClient::renegotiate()
{
  if(!isEstablished())
    return 0;
  return authenticate(*m_pSocket, *m_pCertificate, m_fServerMode);
}

int TSchannelSessionClient::shutdown(bool afSendNotification)
{
  if(!isEstablished())
    return 0;
  m_fEstablished = false;
  ISocket* pSock = m_pSocket;
  m_pSocket = NULL;

  DWORD dwShutdownToken = SCHANNEL_SHUTDOWN;
  SecBufferDesc shutDownBufferDesc;
  SecBuffer shutDownBuffers[1];
  shutDownBufferDesc.cBuffers = 1;
  shutDownBufferDesc.pBuffers = shutDownBuffers;
  shutDownBufferDesc.ulVersion = SECBUFFER_VERSION;
  shutDownBuffers[0].pvBuffer = &dwShutdownToken;
  shutDownBuffers[0].BufferType = SECBUFFER_TOKEN;
  shutDownBuffers[0].cbBuffer = sizeof(dwShutdownToken);

  ::ApplyControlToken(&m_hContext, &shutDownBufferDesc);

  shutDownBuffers[0].BufferType = SECBUFFER_TOKEN;
  shutDownBuffers[0].pvBuffer = NULL;
  shutDownBuffers[0].cbBuffer = NULL;

  // TODO: may be print ulAttribs and stLifetime
  ULONG ulContextAttr = 0;
  TimeStamp tsLifetime;
  SECURITY_STATUS ssResult = ::InitializeSecurityContext(
    &m_hCred, 
    &m_hContext, 
    NULL,
    m_ulContextAttribs | ISC_REQ_ALLOCATE_MEMORY, // mb another flags
    0, 
    0, 
    NULL, 
    0, 
    NULL,
    &shutDownBufferDesc, 
    &ulContextAttr, 
    &tsLifetime);
  if(ssResult < 0)
  {
    ILogR("Error in ::InitializeSecurityContext", ssResult);
    freeInnerResources();
    return ssResult;
  }

  freeInnerResources();

  if(afSendNotification)
  {
    std::auto_ptr<ISocketStream> spStream(
      ISocketStream::create());
    if(!spStream.get())
    {
      ILog("!!! Cannot create ISocketStream");
      freeContextBuff(shutDownBufferDesc);
      return -3;
    }
    int nResult = spStream->attach(*pSock);
    if(nResult)
    {
      ILogR("Error in attach to socket", nResult);
      freeContextBuff(shutDownBufferDesc);
      return nResult;
    }
    nResult = spStream->send(
      shutDownBuffers[0].pvBuffer,
      shutDownBuffers[0].cbBuffer);
    if(nResult)
    {
      ILogR("cannot send shutdown message", nResult);
      freeContextBuff(shutDownBufferDesc);
      return nResult;
    }
  }

  freeContextBuff(shutDownBufferDesc);

  return 0;
}

CredHandle& TSchannelSessionClient::getCreditionals()
{
  return m_hCred;
}

SecHandle& TSchannelSessionClient::getContext()
{
  return m_hContext;
}

bool TSchannelSessionClient::isInServerMode() const
{
  return m_fServerMode;
}

bool TSchannelSessionClient::isEstablished() const
{
  return m_fEstablished;
}

ISocket* TSchannelSessionClient::getAttachedSocket()
{
  return m_pSocket;
}

size_t TSchannelSessionClient::getExtraDataSize() const
{
  return m_vExtraData.size();
}

size_t TSchannelSessionClient::getExtraData(void* apBuffer) const
{
  size_t szCpy = getExtraDataSize();
  memcpy(apBuffer, &m_vExtraData[0], szCpy);
  return szCpy;
}

int TSchannelSessionClient::acquireCredentials(
  const ICertificate& aCertificate)
{
  PCCERT_CONTEXT pcCertContext = &aCertificate.getCertContext();

  SCHANNEL_CRED schCred = {0};
  schCred.dwVersion = SCHANNEL_CRED_VERSION;
  schCred.cCreds = 1;
  schCred.paCred = &pcCertContext;
  schCred.hRootStore = aCertificate.getStoreHandle();
  schCred.grbitEnabledProtocols = c_dwClientAllowedProtocols;
  schCred.dwFlags = m_dwCredFlags;
  
  TimeStamp tsLifetime;
  SECURITY_STATUS ssResult = ::AcquireCredentialsHandle(
      NULL,
      UNISP_NAME,//"Schannel",
      SECPKG_CRED_OUTBOUND,
      NULL,
      &schCred,
      NULL,
      NULL,
      &m_hCred,
      &tsLifetime);
  if(ssResult != SEC_E_OK)
  {
    ILogR("Error in ::AcquireCredentialsHandle", ssResult);
    return ssResult;
  }

  return 0;
}

int TSchannelSessionClient::authenticateOnStream(
  ISocketStream& aSockStream,
  TBlob& avExtraData)
{
  // prepare output
  SecBufferDesc outBuffDesc = {0};
  SecBuffer outSecBuff[2] = {0};
  outBuffDesc.ulVersion = SECBUFFER_VERSION;
  outBuffDesc.cBuffers = 2;
  outBuffDesc.pBuffers = outSecBuff;

  // prepare input
  size_t szBufferSize = 100500;
  TBlob vInputBuffer(szBufferSize, 0); // TODO: what size?
  SecBufferDesc inBuffDesc = {0};
  SecBuffer inSecBuff[2] = {0};
  inBuffDesc.ulVersion = 0;
  inBuffDesc.cBuffers = 2;
  inBuffDesc.pBuffers = inSecBuff;

  SECURITY_STATUS ssResult = SEC_E_OK;
  bool fDone = false;
  bool fFirstCall = true;
  size_t szBufferOffset = 0;
  do
  {
    if(!fFirstCall && 
       (!szBufferOffset || ssResult == SEC_E_INCOMPLETE_MESSAGE))
    {
      size_t szRead = 0;
      int nResult = aSockStream.receive(
        &vInputBuffer[0] + szBufferOffset,
        szBufferSize - szBufferOffset,
        szRead);
      if(nResult)
      {
        ILogR("Cannot receive message during handshake loop", nResult);
        return nResult;
      }
      szBufferOffset += szRead;
    }

    // reset input buffer
    inSecBuff[0].BufferType = SECBUFFER_TOKEN;
    inSecBuff[0].cbBuffer = szBufferOffset;
    inSecBuff[0].pvBuffer = &vInputBuffer[0];

    inSecBuff[1].BufferType = SECBUFFER_EMPTY;
    inSecBuff[1].cbBuffer = 0;
    inSecBuff[1].pvBuffer = NULL;

    // reset output buffer
    outSecBuff[0].BufferType = SECBUFFER_TOKEN;
    outSecBuff[0].cbBuffer = 0;
    outSecBuff[0].pvBuffer = NULL;
  
    outSecBuff[1].BufferType = SECBUFFER_ALERT;
    outSecBuff[1].cbBuffer = 0;
    outSecBuff[1].pvBuffer = NULL;

    // print input
    // temporary stringstream
    std::stringstream logStr;
    logStr << "Token buffer recieved " 
      << inSecBuff[0].cbBuffer << " bytes:";
    ILog(logStr.str());
    ISchannelUtils::printHexDump(inSecBuff[0].cbBuffer, inSecBuff[0].pvBuffer);

    // TODO: may be print ulAttribs and stLifetime
    ULONG ulAttribs = 0;
    TimeStamp tsLifetime;
    ssResult = ::InitializeSecurityContext(
      &m_hCred,
      fFirstCall ? NULL : &m_hContext,
      "i.drozdov",
      m_ulContextAttribs | ASC_REQ_ALLOCATE_MEMORY,
      0,
      0, // not used in Schannel
      &inBuffDesc,
      0,
      (!fFirstCall) ? NULL : &m_hContext,
      &outBuffDesc,
      &ulAttribs,
      &tsLifetime);
    ILogR("::InitializeSecurityContext result", ssResult);
    if(outSecBuff[1].BufferType == SECBUFFER_ALERT &&
       outSecBuff[1].cbBuffer && outSecBuff[1].pvBuffer)
    {
      // show alert if exists
      //ILog(reinterpret_cast<char*>(outSecBuff[1].pvBuffer));
      ILog("\n++ Alert ++");
      ISchannelUtils::printHexDump(
        outSecBuff[1].cbBuffer, 
        outSecBuff[1].pvBuffer);
    }
    fFirstCall = false;
    // need more data
    if(ssResult == SEC_E_INCOMPLETE_MESSAGE)
      continue;
    if(ssResult < 0)
    {
      ILogR("Error in ::InitializeSecurityContext", ssResult);
      ::DeleteSecurityContext(&m_hContext);
      // may be free outBuffDesc? 
      return ssResult;
    }

    if(ssResult == SEC_I_COMPLETE_NEEDED ||
       ssResult == SEC_I_COMPLETE_AND_CONTINUE)
    {
      ssResult = ::CompleteAuthToken(&m_hContext, &outBuffDesc);
      if(ssResult < 0)
      {
        ILogR("Error in ::CompleteAuthToken", ssResult);
        freeContextBuff(outBuffDesc);
        return ssResult;
      }
    }
    
    // TODO: may be provide a valid certificate
    if(ssResult == SEC_I_INCOMPLETE_CREDENTIALS)
    {
      ILogR(
        "Client must provide a valid certificate. Current is not valid",
        ssResult);
      freeContextBuff(outBuffDesc);
      return ssResult;
    }

    fDone = !(
      ssResult == SEC_I_CONTINUE_NEEDED ||
      ssResult == SEC_I_COMPLETE_AND_CONTINUE);

    if(!fDone || (outSecBuff[0].pvBuffer && outSecBuff[0].cbBuffer))
    {
      // print output
      std::stringstream logStr;
      logStr << "Token generated " 
        << outSecBuff[0].cbBuffer << " bytes:";
      ILog(logStr.str());
      ISchannelUtils::printHexDump(outSecBuff[0].cbBuffer, outSecBuff[0].pvBuffer);

      int nResult = aSockStream.send(
        outSecBuff[0].pvBuffer,
        outSecBuff[0].cbBuffer);
      if(nResult)
      {
        ILogR("Cannot send message during handshake loop", nResult);
        freeContextBuff(outBuffDesc);
        return nResult;
      }
    }

    if(inSecBuff[1].BufferType == SECBUFFER_EXTRA)
    {
      if(ssResult == SEC_E_OK)
      {
        avExtraData.resize(inSecBuff[1].cbBuffer);
        memcpy(
          &avExtraData[0], 
          &vInputBuffer[0] + (szBufferOffset - inSecBuff[1].cbBuffer),
          inSecBuff[1].cbBuffer);
        break;
      }
      else
      {
        memcpy(
          &vInputBuffer[0],
          &vInputBuffer[0] + (szBufferOffset - inSecBuff[1].cbBuffer),
          inSecBuff[1].cbBuffer);
        szBufferOffset = inSecBuff[1].cbBuffer;
      }
    }
    else
    {
      szBufferOffset = 0;
    }
  }
  while(!fDone);

  return 0;
}

void TSchannelSessionClient::freeContextBuff(
  SecBufferDesc& aBuffDesc)
{
  for(unsigned short i=0; i<aBuffDesc.cBuffers; ++i)
  {
    SecBuffer* pBuff = aBuffDesc.pBuffers + i;
    if(pBuff->cbBuffer && pBuff->pvBuffer)
      ::FreeContextBuffer(pBuff->pvBuffer);
  }
}

void TSchannelSessionClient::freeInnerResources()
{
  if(m_hCred.dwLower || m_hCred.dwUpper)
  {
    SECURITY_STATUS ssResult = ::FreeCredentialsHandle(&m_hCred);
    if(ssResult != SEC_E_OK)
      ILogR("Error in ::FreeCredentialsHandle", ssResult);

    m_hCred.dwLower = 0;
    m_hCred.dwUpper = 0;
  }

  if(m_hContext.dwLower || m_hContext.dwUpper)
  {
    SECURITY_STATUS ssResult = ::DeleteSecurityContext(&m_hContext);
    if(ssResult != SEC_E_OK)
      ILogR("Error in ::DeleteSecurityContext", ssResult);

    m_hContext.dwLower = 0;
    m_hContext.dwUpper = 0;
  }
}