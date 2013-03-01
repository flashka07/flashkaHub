#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "tSecurityChannelStream.h"

ISecurityChannelStream* ISecurityChannelStream::create()
{
  ISecurityChannelStream* pObject = NULL;
  try
  {
    pObject = new TSecurityChannelStream;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ISecurityChannelStream* ISecurityChannelStream::createInstance()
{
  return new TSecurityChannelStream;
}

ISecurityChannelStream::~ISecurityChannelStream()
{
}