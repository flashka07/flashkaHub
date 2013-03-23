#include "tSoftwareKeyConnection.h"

#ifndef NULL
#define NULL 0
#endif

ISoftwareKeyConnection* ISoftwareKeyConnection::create()
{
  ISoftwareKeyConnection* pObject = NULL;
  try
  {
    pObject = new TSoftwareKeyConnection;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ISoftwareKeyConnection* ISoftwareKeyConnection::createInstance()
{
  return new TSoftwareKeyConnection;
}

ISoftwareKeyConnection::~ISoftwareKeyConnection()
{
}