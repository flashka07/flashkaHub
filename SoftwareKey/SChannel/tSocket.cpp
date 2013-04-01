#include "tSocket.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "iSchannelUtils.h"
#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"

#pragma comment(lib, "Ws2_32.lib")

TSocket::TSocket()
  : m_sock(INVALID_SOCKET),
    m_pLog(IApcLog::getLog("TSocket"))
{
}

TSocket::~TSocket()
{
  disconnect();
}

int TSocket::connect(
  const std::string& astrAddress,
  const std::string& astrPort)
{
  disconnect();

  addrinfo* pResultAddrInfo = NULL;
  addrinfo hintsAddrInfo = {0};
  hintsAddrInfo.ai_family = AF_INET;
  hintsAddrInfo.ai_socktype = SOCK_STREAM;
  hintsAddrInfo.ai_protocol = IPPROTO_TCP;

  // Resolve the server address and port
  int nResult = getaddrinfo(
    astrAddress.c_str(),
    astrPort.c_str(), 
    &hintsAddrInfo, 
    &pResultAddrInfo);
  if(nResult) 
  {
    __L_BADH(m_pLog, "Cannot getaddrinfo", nResult);
    return nResult;
  }
  
  // Attempt to connect to an address until one succeeds
  for(addrinfo* ptr = pResultAddrInfo; 
      ptr != NULL; 
      ptr=ptr->ai_next) 
  {
    // Create a SOCKET for connecting to server
    m_sock = ::socket(
      ptr->ai_family, 
      ptr->ai_socktype, 
      ptr->ai_protocol);
    if(m_sock == INVALID_SOCKET) 
    {
      nResult = ::GetLastError();
      __L_BADH(m_pLog, "Cannot create socket", nResult);
      freeaddrinfo(pResultAddrInfo);
      return nResult;
    }

    // Connect to server.
    int nResult = ::connect(m_sock,
      ptr->ai_addr, 
      static_cast<int>(ptr->ai_addrlen));
    if(nResult == SOCKET_ERROR) 
    {
      ::closesocket(m_sock);
      m_sock = INVALID_SOCKET;
      continue;
    }
    break;
  }
  freeaddrinfo(pResultAddrInfo);

  if(!isEstablished())
  {
    int nResult = ::WSAGetLastError();
    __L_BADH(m_pLog, "Socked is not connected", nResult);
    if(nResult)
      return nResult;
    else
      return -20;
  }

  return 0;
}

void TSocket::disconnect()
{
  if(!isEstablished())
    return;

  shutdown(enSHUTDOWN_BOTH);
  ::closesocket(m_sock);
  m_sock = INVALID_SOCKET;
}

int TSocket::listen(
  int anMaxConnections,
  const std::string& astrPort,
  const std::string& astrAddress)
{
  disconnect();

  SOCKET sockListen = NULL;

  addrinfo* pResultAddrInfo = NULL;
  addrinfo hintsAddrInfo = {0};
  hintsAddrInfo.ai_family = AF_INET;
  hintsAddrInfo.ai_socktype = SOCK_STREAM;
  hintsAddrInfo.ai_protocol = IPPROTO_TCP;

  // Resolve the server address and port
  PCSTR pAddress = astrAddress.empty() ? NULL : astrAddress.c_str();
  int nResult = ::getaddrinfo(
    pAddress,
    astrPort.c_str(), 
    &hintsAddrInfo, 
    &pResultAddrInfo);
  if(nResult) 
  {
    __L_BADH(m_pLog, "Cannot getaddrinfo", nResult);
    return nResult;
  }

  sockListen = ::socket(
    pResultAddrInfo->ai_family, 
    pResultAddrInfo->ai_socktype, 
    pResultAddrInfo->ai_protocol);
  if(sockListen == INVALID_SOCKET)
  {
    nResult = ::GetLastError();
    __L_BADH(m_pLog, "cannot create sockListen", nResult);
    ::freeaddrinfo(pResultAddrInfo);
    return nResult;
  }

  nResult = ::bind(
    sockListen, 
    pResultAddrInfo->ai_addr, 
    static_cast<int>(pResultAddrInfo->ai_addrlen));
  if(nResult == SOCKET_ERROR)
  {
    nResult = ::GetLastError();
    __L_BADH(m_pLog, "cannot bind to socket", nResult);
    ::freeaddrinfo(pResultAddrInfo);
    return nResult;
  }

  ::freeaddrinfo(pResultAddrInfo);

  nResult = ::listen(sockListen, anMaxConnections);
  if(nResult == SOCKET_ERROR)
  {
    nResult = ::GetLastError();
    __L_BADH(m_pLog, "cannot listen socket", nResult);
    return nResult;
  }

  m_sock = sockListen;
  __L_TRK(m_pLog, "> Listening...");
  return 0;
}

int TSocket::accept(
  unsigned int aunTimeout,
  ISocket& aConnectedSocket)
{
  if(aunTimeout)
  {
    fd_set fdsRead = {0};
    FD_SET(m_sock, &fdsRead);
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
      return 0; // timeout
  }

  SOCKADDR sockAddrIncoming = {0};
  int nSize = sizeof(sockAddrIncoming);
  SOCKET sockClient = ::accept(
    m_sock, 
    &sockAddrIncoming,
    &nSize);
  if(sockClient == INVALID_SOCKET)
  {
    int nResult = ::GetLastError();
    __L_BADH(m_pLog, "cannot accept client socket", nResult);
    return nResult;
  }

  aConnectedSocket.attach(sockClient);
  __L_TRK(m_pLog, "> Connection accepted");
  return 0;
}

int TSocket::listenAndAccept(
  const std::string& astrPort,
  const std::string& astrAddress)
{
  int nResult = listen(
    1,
    astrPort,
    astrAddress);
  if(nResult)
  {
    __L_BADH(m_pLog, "error in listen", nResult);
    return nResult;
  }

  TSocket incSock;
  nResult = accept(0, incSock);
  if(nResult)
  {
    __L_BADH(m_pLog, "error in accept", nResult);
    return nResult;
  }

  disconnect();
  swap(incSock);
  return 0;
}

void TSocket::shutdown(HowShutdown aHow)
{
  if(!isEstablished())
    return;

  int nResult = ::shutdown(m_sock, aHow);
  if(nResult)
  {
    nResult = ::WSAGetLastError();
    __L_BADH(m_pLog, "Cannot shutdown socket", nResult);
    __L_BAD(m_pLog, ISchannelUtils::printError(nResult));
  }
}

bool TSocket::isEstablished() const
{
  return m_sock != INVALID_SOCKET;
}

SOCKET TSocket::getInnerSocket() const
{
  return m_sock;
}

void TSocket::attach(const SOCKET& aSock)
{
  disconnect();
  m_sock = aSock;
}

void TSocket::swap(TSocket& aRhs)
{
  SOCKET tmp = m_sock;
  m_sock = aRhs.getInnerSocket();
  aRhs.m_sock = tmp;
}