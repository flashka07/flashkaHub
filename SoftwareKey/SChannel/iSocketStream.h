#pragma once
#include "iByteStream.h"

class ISocket;

class __declspec(dllexport) ISocketStream : public IByteStream
{
public:
  static ISocketStream* create();
  static ISocketStream* createInstance();

  virtual ~ISocketStream();

  virtual int attach(ISocket& aSocket) = 0;
  virtual int detach() = 0;

  virtual bool isAttached() const = 0;
};