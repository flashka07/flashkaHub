#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "tSecurityChannelStream.h"

#include "iSecurityChannel.h"
#include "iSocketStream.h"
#include "iSchannelUtils.h"

#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"

#pragma comment(lib, "Secur32.lib")

TSecurityChannelStream::TSecurityChannelStream()
  : m_pSecurityChannel(NULL),
    m_pSocketStream(NULL),
    m_szHeaderLength(0),
    m_szMessageLength(0),
    m_szTrailerLength(0),
    m_pLog(IApcLog::getLog("TSecurityChannelStream"))
{
  ::memset(&m_outBuffDesc, 0, sizeof(m_outBuffDesc));
  ::memset(&m_outSecBuff, 0, sizeof(m_outSecBuff));
  ::memset(&m_inBuffDesc, 0, sizeof(m_inBuffDesc));
  ::memset(&m_inSecBuff, 0, sizeof(m_inSecBuff));
}

TSecurityChannelStream::~TSecurityChannelStream()
{
  if(isAttached())
    detach();
}

int TSecurityChannelStream::attach(ISecurityChannel& aChannel)
{
  if(isAttached())
    detach();

  if(!aChannel.isEstablished())
  {
    __L_BAD(m_pLog, "Security session is not established!");
    return -5;
  }

  int nResult = getStreamSizes(aChannel);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in getStreamSizes", nResult);
    return nResult;
  }

  nResult = initBuffers();
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in initBuffers", nResult);
    return nResult;
  }

  m_pSocketStream = ISocketStream::create();
  nResult = m_pSocketStream->attach(
    *aChannel.getAttachedSocket());
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot attach socket", nResult);
    return nResult;
  }

  m_pSecurityChannel = &aChannel;
  return 0;
}

int TSecurityChannelStream::detach()
{
  if(m_pSocketStream)
    delete m_pSocketStream;

  m_pSecurityChannel = NULL;
  return 0;
}

bool TSecurityChannelStream::isAttached() const
{
  return m_pSecurityChannel != NULL;
}

int TSecurityChannelStream::send(
  const void* apMessage,
  size_t aszLength)
{
  if(!isAttached())
  {
    __L_BAD(m_pLog, "Stream is not attached");
    return -4;
  }

  if(!m_pSecurityChannel->isEstablished())
  {
    __L_BAD(m_pLog, "Security session is not established!");
    return -5;
  }

  while(aszLength > 0)
  {
    size_t szEncryptSize = min(
      aszLength, 
      m_szMessageLength);
    
    m_outSecBuff[1].cbBuffer = szEncryptSize;
    m_outSecBuff[1].pvBuffer = &m_vOutBuffer[0] + m_outSecBuff[0].cbBuffer;
    memcpy(m_outSecBuff[1].pvBuffer, apMessage, szEncryptSize);

    m_outSecBuff[2].cbBuffer = m_szTrailerLength;
    m_outSecBuff[2].pvBuffer = static_cast<BYTE*>(m_outSecBuff[1].pvBuffer) 
      + szEncryptSize;

    SECURITY_STATUS ssResult = ::EncryptMessage(
      &m_pSecurityChannel->getContext(),
      0,
      &m_outBuffDesc,
      0);
    if(ssResult != SEC_E_OK)
    {
      __L_BADH(m_pLog, "Error in ::EncryptMessage", ssResult);
      return ssResult;
    }
    
    size_t szCurBuffSize = m_outSecBuff[0].cbBuffer 
      + m_outSecBuff[1].cbBuffer + m_outSecBuff[2].cbBuffer;
    __L_ANY(m_pLog, "\nEncrypted:");
    __L_ANY(
      m_pLog, 
      ISchannelUtils::printHexDump(
        szCurBuffSize,
        m_outSecBuff[0].pvBuffer));

    int nResult = m_pSocketStream->send(
      m_outSecBuff[0].pvBuffer,
      szCurBuffSize);
    if(nResult)
    {
      __L_BADH(m_pLog, "cannot send encrypted message", nResult);
      return nResult;
    }

    apMessage = static_cast<const BYTE*>(apMessage) + szEncryptSize;
    aszLength -= szEncryptSize;
  }

  return 0;
}

int TSecurityChannelStream::receive(
  void* apBuffer,
  size_t aszBufferSize,
  size_t& aszReceivedBytes,
  unsigned int aunTimeout)
{
  if(!isAttached())
  {
    __L_BAD(m_pLog, "Stream is not attached");
    return -4;
  }

  if(!m_pSecurityChannel->isEstablished())
  {
    __L_BAD(m_pLog, "Security session is not established!");
    return -5;
  }

  size_t szBufferOffset = 0;
  SECURITY_STATUS ssResult = SEC_E_INCOMPLETE_MESSAGE;
  while(true)
  {
    if(!szBufferOffset || ssResult == SEC_E_INCOMPLETE_MESSAGE)
    {
      size_t szRead = 0;
      int nResult = m_pSocketStream->receive(
        &m_vInBuffer[0] + szBufferOffset,
        m_vInBuffer.size() - szBufferOffset,
        szRead,
        aunTimeout);
      if(nResult)
      {
        __L_BADH(m_pLog, "Cannot receive message during handshake loop", nResult);
        return nResult;
      }
      if(!szRead)
      {
        __L_TRK(m_pLog, "Receive time out!");
        return -31;
      }
      szBufferOffset += szRead;
    }

    m_inSecBuff[0].BufferType = SECBUFFER_DATA;
    m_inSecBuff[0].cbBuffer = szBufferOffset;
    m_inSecBuff[0].pvBuffer = &m_vInBuffer[0];
    
    m_inSecBuff[1].BufferType = SECBUFFER_EMPTY;
    m_inSecBuff[1].cbBuffer = 0;
    m_inSecBuff[1].pvBuffer = NULL;

    m_inSecBuff[2].BufferType = SECBUFFER_EMPTY;
    m_inSecBuff[2].cbBuffer = 0;
    m_inSecBuff[2].pvBuffer = NULL;

    m_inSecBuff[3].BufferType = SECBUFFER_EMPTY;
    m_inSecBuff[3].cbBuffer = 0;
    m_inSecBuff[3].pvBuffer = NULL;

    ssResult = ::DecryptMessage(
      &m_pSecurityChannel->getContext(),
      &m_inBuffDesc,
      0,
      NULL);
    if(ssResult < 0 && 
       ssResult != SEC_I_RENEGOTIATE &&
       ssResult != SEC_I_CONTEXT_EXPIRED &&
       ssResult != SEC_E_INCOMPLETE_MESSAGE)
    {
      __L_BADH(m_pLog, "Error in ::DecryptMessage", ssResult);
      return ssResult;
    }

    // need more data
    if(ssResult == SEC_E_INCOMPLETE_MESSAGE)
      continue;

    if(ssResult == SEC_I_CONTEXT_EXPIRED)
    {
      __L_TRK(m_pLog, "> Context expired. Shutting down channel...");
      int nResult = m_pSecurityChannel->shutdown(false);
      if(nResult)
      {
        __L_BADH(m_pLog, "Error shutdown Security Channel", nResult);
        return nResult;
      }
      return 0;
    }

    SecBuffer *pData = NULL;
    SecBuffer *pExtra = NULL;
    for(short i=0; i<4; ++i)
    {
      if(m_inSecBuff[i].BufferType == SECBUFFER_DATA)
        pData = &m_inSecBuff[i];
      if(m_inSecBuff[i].BufferType == SECBUFFER_EXTRA )
        pExtra = &m_inSecBuff[i];
    }

    if(ssResult == SEC_E_OK && pData)
    {
      // TODO: may be only when pExtra == NULL
      aszReceivedBytes = min(m_vInBuffer.size(), pData->cbBuffer);
      memcpy(apBuffer, pData->pvBuffer, aszReceivedBytes);
      return 0;
    }

    if(pExtra)
    {
      memcpy(
        &m_vInBuffer[0],
        &m_vInBuffer[0] + (szBufferOffset - pExtra->cbBuffer),
        pExtra->cbBuffer);
      szBufferOffset = pExtra->cbBuffer;
    }
    else
    {
      szBufferOffset = 0;
    }

    if(ssResult == SEC_I_RENEGOTIATE)
    {
      int nResult = m_pSecurityChannel->renegotiate();
      if(nResult)
      {
        __L_BADH(m_pLog, "Error while renegotiate channel", nResult);
        return nResult;
      }
      size_t szAuthExtraSize = m_pSecurityChannel->getExtraDataSize();
      if(szAuthExtraSize)
      {
        TBlob vExtra(szAuthExtraSize);
        m_pSecurityChannel->getExtraData(&vExtra[0]);
        memcpy(
          &m_vInBuffer[0],
          &vExtra[0],
          szAuthExtraSize);
        szBufferOffset = szAuthExtraSize;
      }
    }
  }

  return 0;
}

int TSecurityChannelStream::getStreamSizes(
  ISecurityChannel& aChannel)
{
  if(!aChannel.isEstablished())
  {
    __L_BAD(m_pLog, "Security session is not established!");
    return -5;
  }

  SecPkgContext_StreamSizes streamSizes = {0};
  SECURITY_STATUS ssResult = ::QueryContextAttributes(
    &aChannel.getContext(),
    SECPKG_ATTR_STREAM_SIZES,
    &streamSizes);
  if(ssResult != SEC_E_OK)
  {
    __L_BADH(m_pLog, "Error in ::QueryContextAttributes", ssResult);
    return ssResult;
  }

  m_szHeaderLength = streamSizes.cbHeader;
  m_szMessageLength = streamSizes.cbMaximumMessage;
  m_szTrailerLength = streamSizes.cbTrailer;
  // TODO: get block size And optimize

  return 0;
}

int TSecurityChannelStream::initBuffers()
{
  size_t szTotalSize = m_szHeaderLength
    + m_szMessageLength
    + m_szTrailerLength;

  m_vInBuffer.resize(szTotalSize, 0);
  m_vOutBuffer.resize(szTotalSize, 0);

  // prepare output
  m_outBuffDesc.cBuffers = 4;
  m_outBuffDesc.pBuffers = m_outSecBuff;

  m_outSecBuff[0].BufferType = SECBUFFER_STREAM_HEADER;
  m_outSecBuff[0].cbBuffer = m_szHeaderLength;
  m_outSecBuff[0].pvBuffer = &m_vOutBuffer[0];

  m_outSecBuff[1].BufferType = SECBUFFER_DATA;

  m_outSecBuff[2].BufferType = SECBUFFER_STREAM_TRAILER;

  m_outSecBuff[3].BufferType = SECBUFFER_EMPTY;
  m_outSecBuff[3].pvBuffer = NULL;
  m_outSecBuff[3].cbBuffer = 0;

  // prepare input
  m_inBuffDesc.cBuffers = 4;
  m_inBuffDesc.pBuffers = m_inSecBuff;

  return 0;
}