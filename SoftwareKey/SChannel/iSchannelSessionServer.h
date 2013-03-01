#pragma once
#include "iSecurityChannel.h"

class __declspec(dllexport) ISchannelSessionServer 
  : public ISecurityChannel
{
public:
  static ISchannelSessionServer* create();
  static ISchannelSessionServer* createInstance();

  virtual ~ISchannelSessionServer();
};