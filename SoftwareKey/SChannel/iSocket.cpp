#include <winsock.h>
#include "tSocket.h"

ISocket* ISocket::create()
{
  ISocket* pObject = NULL;
  try
  {
    pObject = new TSocket;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ISocket* ISocket::createInstance()
{
  return new TSocket;
}

ISocket::~ISocket()
{
}

int ISocket::maxConnectionQueue()
{
  return SOMAXCONN;
}