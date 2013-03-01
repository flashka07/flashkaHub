#include "tSocket.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "iLog.h"

TSocket::TSocket()
  :m_sock(INVALID_SOCKET)
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
    ILogR("Cannot getaddrinfo", nResult);
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
      ILogR("Cannot create socket", nResult);
      freeaddrinfo(pResultAddrInfo);
      return nResult;
    }

    // Connect to server.
    int nResult = ::connect(m_sock,
      ptr->ai_addr, 
      static_cast<int>(ptr->ai_addrlen));
    if(nResult == SOCKET_ERROR) 
    {
      disconnect();
      m_sock = INVALID_SOCKET;
      continue;
    }
    break;
  }

  if(!isEstablished())
  {
    int nResult = ::WSAGetLastError();
    ILogR("Socked is not connected", nResult);
    freeaddrinfo(pResultAddrInfo);
    return nResult;
  }

  freeaddrinfo(pResultAddrInfo);

  return 0;
}

int TSocket::listenAndAccept(
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
    ILogR("Cannot getaddrinfo", nResult);
    return nResult;
  }

  sockListen = ::socket(
    pResultAddrInfo->ai_family, 
    pResultAddrInfo->ai_socktype, 
    pResultAddrInfo->ai_protocol);
  if(sockListen == INVALID_SOCKET)
  {
    nResult = ::GetLastError();
    ILogR("cannot create sockListen", nResult);
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
    ILogR("cannot bind to socket", nResult);
    ::freeaddrinfo(pResultAddrInfo);
    return nResult;
  }

  ::freeaddrinfo(pResultAddrInfo);

  nResult = ::listen(sockListen, 1);
  if(nResult == SOCKET_ERROR)
  {
    nResult = ::GetLastError();
    ILogR("cannot listen socket", nResult);
    return nResult;
  }

  ILog("> Listening...");

  SOCKADDR sockAddrIncoming = {0};
  int nSize = sizeof(sockAddrIncoming);
  SOCKET sockClient = NULL;
  sockClient = ::accept(
    sockListen, 
    &sockAddrIncoming,
    &nSize);
  if(sockClient == INVALID_SOCKET)
  {
    nResult = ::GetLastError();
    ILogR("cannot accept client socket", nResult);
    return nResult;
  }

  ILog("> Client connected");

  ::closesocket(sockListen);

  m_sock = sockClient;
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

void TSocket::shutdown(HowShutdown aHow)
{
  if(!isEstablished())
    return;

  int nResult = ::shutdown(m_sock, aHow);
  if(nResult)
  {
    nResult = ::WSAGetLastError();
    ILogR("Cannot shutdown socket", nResult);
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