#pragma once
#include <string>

typedef unsigned int SOCKET;

class __declspec(dllexport) ISocket
{
public:
  enum HowShutdown
  {
    enSHUTDOWN_RECIEVE = 0,
    enSHUTDOWN_SEND = 1,
    enSHUTDOWN_BOTH = 2,
  };
public:
  static ISocket* create();
  static ISocket* createInstance();

  virtual ~ISocket();

  virtual int connect(
    const std::string& astrAddress,
    const std::string& astrPort) = 0;

  virtual void disconnect() = 0;

  // start listening socket
  virtual int listen(
    int anMaxConnections,
    const std::string& astrPort,
    const std::string& astrAddress = "") = 0;

  // accept incoming connection
  // for check timed out call isEstablished()
  // (timeout in miliseconds)
  virtual int accept(
    unsigned int aunTimeout,
    ISocket& aConnectedSocket) = 0;

  // listen and accept only 1 connection
  // this socket can be used for transfer
  virtual int listenAndAccept(
    const std::string& astrPort,
    const std::string& astrAddress = "") = 0;

  virtual void shutdown(
    HowShutdown aHow = enSHUTDOWN_BOTH) = 0;

  virtual bool isEstablished() const = 0;

  virtual SOCKET getInnerSocket() const = 0;

  // attach to existing winapi socket
  virtual void attach(const SOCKET& aSock) = 0;

  static int maxConnectionQueue();
};