#include "tSchannelSessionClient.h"

#ifndef NULL
#define NULL 0
#endif

ISchannelSessionClient* ISchannelSessionClient::create()
{
  ISchannelSessionClient* pObject = NULL;
  try
  {
    pObject = new TSchannelSessionClient;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ISchannelSessionClient* ISchannelSessionClient::createInstance()
{
  return new TSchannelSessionClient;
}

ISchannelSessionClient::~ISchannelSessionClient()
{
}