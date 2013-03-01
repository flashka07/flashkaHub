#include "tSocketStream.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "iSocket.h"
#include "iLog.h"

TSocketStream::TSocketStream()
 :m_pSocket(NULL)
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
    ILog("Sending NULL buffer");
    return 0;
  }

  int nResult = sendBytes(
    reinterpret_cast<void*>(&aszLength), 
    sizeof(aszLength));
  if(nResult)
  {
    ILogR("Error while sending Length", nResult);
    return nResult;
  }

  nResult = sendBytes(apMessage, aszLength);
  if(nResult)
  {
    ILogR("Error while sending Message", nResult);
    return nResult;
  }

  return 0;
}

int TSocketStream::receive(
  void* apBuffer,
  size_t aszBufferSize,
  size_t& aszReceivedBytes)
{
  if(!apBuffer)
  {
    ILog("Reading into NULL buffer");
    return 0;
  }

  size_t szRead = 0;
  size_t szLength = 0;

  int nResult = receiveBytes(&szLength, sizeof(szLength), szRead);
  if(nResult)
  {
    ILogR("Error while receiving Length", nResult);
    return nResult;
  }

  if(sizeof(szLength) != szRead)
  {
    ILog("Wrong received Length");
    return -2;
  }

  if(szLength > aszBufferSize)
  {
    // TODO: recieve into temp buffer, then copy data on next call
    // (if taken enough buffer, of course)
    ILog("Too small buffer");
    return -2;
  }

  nResult = receiveBytes(apBuffer, szLength, szRead);
  if(nResult)
  {
    ILogR("Error while receiving Length", nResult);
    return nResult;
  }

  if(szRead != szLength)
  {
    ILog("Wrong received Message");
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
    ILog("Stream is not attached to socket!");
    return -1;
  }

  long int lnRemaining = aszBuf;

  while(lnRemaining) 
  {
    ILog("+ Sending");
    int nSent = ::send(
      m_pSocket->getInnerSocket(), 
      reinterpret_cast<const char*>(apBuf), 
      lnRemaining, 
      0);
    if(SOCKET_ERROR == nSent) 
    {
      int nResult = ::WSAGetLastError();
      ILogR("error in ::send", nResult);
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
  size_t& aszRead)
{
  if(!isAttached())
  {
    ILog("Stream is not attached to socket!");
    return -1;
  }
  
  long int lnRemaining = aszBuf;

  while(lnRemaining) 
  {
    ILog("- Receiving");
    int nRead = ::recv(
      m_pSocket->getInnerSocket(), 
      reinterpret_cast<char*>(apBuf), 
      lnRemaining, 
      0);
    if(0 == nRead)
    {
      ILog("Socket connection closed");
      m_pSocket->disconnect();
      detach();
      break;
    }

    if(SOCKET_ERROR == nRead) 
    {
      int nResult = ::WSAGetLastError();
      ILogR("error in ::recv", nResult);
      return nResult;
    }

    lnRemaining -= nRead;
    apBuf = reinterpret_cast<char*>(apBuf) + nRead;
  }

  aszRead = aszBuf - lnRemaining;
  return 0;
}