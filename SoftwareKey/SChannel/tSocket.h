#pragma once
#include "iSocket.h"

class TSocket : public ISocket
{
public:
  TSocket();
  ~TSocket();

  int connect(
    const std::string& astrAddress,
    const std::string& astrPort);

  int listenAndAccept(
    const std::string& astrPort,
    const std::string& astrAddress);

  void disconnect();

  void shutdown(HowShutdown aHow);

  bool isEstablished() const;

  SOCKET getInnerSocket() const;

private:
  SOCKET m_sock;
};