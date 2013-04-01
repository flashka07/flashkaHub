#include "tSocketStream.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "iSocket.h"
#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"

#pragma comment(lib, "Ws2_32.lib")

TSocketStream::TSocketStream()
  : m_pSocket(NULL),
    m_pLog(IApcLog::getLog("TSocketStream"))
{
}

TSocketStream::~TSocketStream()
{
  if(isAttached())
    detach();
}

int TSocketStream::attach(ISocket& aSocket)
{
  if(isAttached())
    detach();
  m_pSocket = &aSocket;
  return 0;
}

int TSocketStream::detach()
{
  m_pSocket = NULL;
  return 0;
}

int TSocketStream::send(
  const void* apMessage,
  size_t aszLength)
{
  if(!apMessage)
  {
    __L_TRK(m_pLog, "Sending NULL buffer");
    return 0;
  }

  int nResult = sendBytes(
    reinterpret_cast<void*>(&aszLength), 
    sizeof(aszLength));
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while sending Length", nResult);
    return nResult;
  }

  nResult = sendBytes(apMessage, aszLength);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while sending Message", nResult);
    return nResult;
  }

  return 0;
}

int TSocketStream::receive(
  void* apBuffer,
  size_t aszBufferSize,
  size_t& aszReceivedBytes,
  unsigned int aunTimeout)
{
  if(!apBuffer)
  {
    __L_BAD(m_pLog, "Reading into NULL buffer");
    return 0;
  }

  size_t szRead = 0;
  size_t szLength = 0;

  int nResult = receiveBytes(
    &szLength, 
    sizeof(szLength), 
    szRead,
    aunTimeout);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while receiving Length", nResult);
    return nResult;
  }

  if(sizeof(szLength) != szRead)
  {
    __L_BAD(m_pLog, "Wrong received Length or timed out");
    return -2;
  }

  if(szLength > aszBufferSize)
  {
    // TODO: recieve into temp buffer, then copy data on next call
    // (if taken enough buffer, of course)
    __L_BAD(m_pLog, "Too small buffer");
    return -2;
  }

  nResult = receiveBytes(
    apBuffer, 
    szLength, 
    szRead,
    aunTimeout);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error while receiving Length", nResult);
    return nResult;
  }

  if(szRead != szLength)
  {
    __L_BAD(m_pLog, "Wrong received Message or timed out");
    return -2;
  }

  aszReceivedBytes = szRead;

  return 0;
}

bool TSocketStream::isAttached() const
{
  return m_pSocket != NULL;
}

int TSocketStream::sendBytes(
  const void* apBuf, 
  size_t aszBuf)
{
  if(!isAttached())
  {
    __L_BAD(m_pLog, "Stream is not attached to socket!");
    return -1;
  }

  long int lnRemaining = aszBuf;

  while(lnRemaining) 
  {
    __L_TRK(m_pLog, "+ Sending");
    int nSent = ::send(
      m_pSocket->getInnerSocket(), 
      reinterpret_cast<const char*>(apBuf), 
      lnRemaining, 
      0);
    if(SOCKET_ERROR == nSent) 
    {
      int nResult = ::WSAGetLastError();
      __L_BADH(m_pLog, "error in ::send", nResult);
      return nResult;
    }

    apBuf = reinterpret_cast<const char*>(apBuf) + nSent;
    lnRemaining -= nSent;
  }

  return 0;
}

int TSocketStream::receiveBytes(
  void* apBuf, 
  size_t aszBuf, 
  size_t& aszRead,
  unsigned int aunTimeout)
{
  if(!isAttached())
  {
    __L_BAD(m_pLog, "Stream is not attached to socket!");
    return -1;
  }
  
  long int lnRemaining = aszBuf;

  while(lnRemaining) 
  {
    __L_TRK(m_pLog, "- Receiving");
    if(aunTimeout)
    {
      fd_set fdsRead = {0};
      FD_SET(m_pSocket->getInnerSocket(), &fdsRead);
      TIMEVAL interval = {0};
      interval.tv_sec = aunTimeout / 1000; // from ms to s
      interval.tv_usec = (aunTimeout % 1000) * 1000; // from ms to us (micro)

      int nResult = ::select(
        0,
        &fdsRead,
        NULL,
        NULL,
        &interval);
      if(nResult == SOCKET_ERROR)
      {
        nResult = ::WSAGetLastError();
        __L_BADH(m_pLog, "Cannot shutdown socket", nResult);
        return nResult;
      }
      if(!nResult)
      {
        aszRead = aszBuf - lnRemaining;
        return 0; // timeout
      }
    }

    int nRead = ::recv(
      m_pSocket->getInnerSocket(), 
      reinterpret_cast<char*>(apBuf), 
      lnRemaining, 
      0);
    if(0 == nRead)
    {
      __L_TRK(m_pLog, "Socket connection closed");
      m_pSocket->disconnect();
      detach();
      break;
    }

    if(SOCKET_ERROR == nRead) 
    {
      int nResult = ::WSAGetLastError();
      __L_BADH(m_pLog, "error in ::recv", nResult);
      return nResult;
    }

    lnRemaining -= nRead;
    apBuf = reinterpret_cast<char*>(apBuf) + nRead;
  }

  aszRead = aszBuf - lnRemaining;
  return 0;
}