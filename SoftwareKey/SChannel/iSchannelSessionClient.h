#pragma once
#include "iSecurityChannel.h"

class __declspec(dllexport) ISchannelSessionClient 
  : public ISecurityChannel
{
public:
  static ISchannelSessionClient* create();
  static ISchannelSessionClient* createInstance();

  virtual ~ISchannelSessionClient();
};