#pragma once
#include "iByteStream.h"

class ISecurityChannel;

class __declspec(dllexport) ISecurityChannelStream : public IByteStream
{
public:
  static ISecurityChannelStream* create();
  static ISecurityChannelStream* createInstance();

  virtual ~ISecurityChannelStream();

  virtual int attach(ISecurityChannel& aChannel) = 0;
  virtual int detach() = 0;

  virtual bool isAttached() const = 0;
};