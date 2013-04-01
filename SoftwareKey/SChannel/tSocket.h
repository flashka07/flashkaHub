#pragma once
#include "iSocket.h"

class IApcLog;

class TSocket : public ISocket
{
public:
  TSocket();
  ~TSocket();

  int connect(
    const std::string& astrAddress,
    const std::string& astrPort);
  
  void disconnect();

  // start listening socket
  int listen(
    int anMaxConnections,
    const std::string& astrPort,
    const std::string& astrAddress);

  // accept incoming connection
  // for check timed out call isEstablished()
  int accept(
    unsigned int aunTimeout,
    ISocket& aConnectedSocket);

  // listen and accept only 1 connection
  // this socket can be used for transfer
  int listenAndAccept(
    const std::string& astrPort,
    const std::string& astrAddress);  

  void shutdown(HowShutdown aHow);

  bool isEstablished() const;

  SOCKET getInnerSocket() const;

  // attach to existing winapi socket
  void attach(const SOCKET& aSock);
  
private:
  void swap(TSocket& aRhs);

  // class data
  SOCKET m_sock;
  
  IApcLog* m_pLog;
};