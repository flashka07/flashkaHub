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

  virtual int listenAndAccept(
    const std::string& astrPort,
    const std::string& astrAddress = "") = 0;

  virtual void shutdown(
    HowShutdown aHow = enSHUTDOWN_BOTH) = 0;

  virtual bool isEstablished() const = 0;

  virtual SOCKET getInnerSocket() const = 0;
};