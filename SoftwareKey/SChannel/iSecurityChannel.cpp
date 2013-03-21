#include "tSecurityChannel.h"

#ifndef NULL
#define NULL 0
#endif

ISecurityChannel* ISecurityChannel::create()
{
  ISecurityChannel* pObject = NULL;
  try
  {
    pObject = new TSecurityChannel;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ISecurityChannel* ISecurityChannel::createInstance()
{
  return new TSecurityChannel;
}

ISecurityChannel::~ISecurityChannel()
{
}