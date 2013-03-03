#include <iostream>
#include "Socket.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "Ws2_32.lib")

Socket::Socket()
  :m_pSocket(NULL)
{
  int nResutl = initialize();
  if(nResutl)
    throw std::exception("Cannot initialize Socket");
}

Socket::~Socket()
{
  if(m_pSocket)
    delete m_pSocket;
  ::WSACleanup();
}

int Socket::listen(const std::string& astrPort)
{
  addrinfo hints = {0};
  addrinfo *pResultAddrInfo = NULL;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  int nResult = getaddrinfo(
    NULL,
    astrPort.c_str(),
    &hints,
    &pResultAddrInfo);
  if(nResult)
  {
    std::cout << "error in getaddrinfo()" << gai_strerror(nResult) << '\n';
    return nResult;
  }

  m_pSocket = new SOCKET;
  *m_pSocket = socket(
    pResultAddrInfo->ai_family, 
    pResultAddrInfo->ai_socktype, 
    pResultAddrInfo->ai_protocol);
  if (*m_pSocket == INVALID_SOCKET) 
  {
    nResult = WSAGetLastError();
    std::cout << "error in socket()" << gai_strerror(nResult) << '\n';
    freeaddrinfo(pResultAddrInfo);
    return nResult;
  }

  nResult = bind(
    *m_pSocket, 
    pResultAddrInfo->ai_addr, 
    (int)pResultAddrInfo->ai_addrlen);
  if (nResult == SOCKET_ERROR) 
  {
    nResult = WSAGetLastError();
    std::cout << "error in bind()" << gai_strerror(nResult) << '\n';
    closesocket(*m_pSocket);
    freeaddrinfo(pResultAddrInfo);
    return nResult;
  }

  freeaddrinfo(pResultAddrInfo);

  if (::listen(*m_pSocket, SOMAXCONN) == SOCKET_ERROR) 
  {
    nResult = WSAGetLastError();
    std::cout << "error in listen()" << gai_strerror(nResult) << '\n';
    closesocket(*m_pSocket);
    return nResult;
  }

  return 0;
}

int Socket::initialize()
{
  WSADATA wsaData;
  int nResult = ::WSAStartup(MAKEWORD(2,2), &wsaData);
  if(nResult)
    return nResult;

  if (LOBYTE(wsaData.wVersion) != 2 || 
      HIBYTE(wsaData.wVersion) != 2) 
  {
    ::WSACleanup();
    return 1;
  }

  return 0;
}