#include "tSocketStream.h"
#ifndef NULL
#define NULL 0
#endif

ISocketStream* ISocketStream::create()
{
  ISocketStream* pObject = NULL;
  try
  {
    pObject = new TSocketStream;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ISocketStream* ISocketStream::createInstance()
{
  return new TSocketStream;
}

ISocketStream::~ISocketStream()
{
}