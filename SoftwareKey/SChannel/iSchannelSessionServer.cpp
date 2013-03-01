#include "tSchannelSessionServer.h"

#ifndef NULL
#define NULL 0
#endif

ISchannelSessionServer* ISchannelSessionServer::create()
{
  ISchannelSessionServer* pObject = NULL;
  try
  {
    pObject = new TSchannelSessionServer;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ISchannelSessionServer* ISchannelSessionServer::createInstance()
{
  return new TSchannelSessionServer;
}

ISchannelSessionServer::~ISchannelSessionServer()
{
}