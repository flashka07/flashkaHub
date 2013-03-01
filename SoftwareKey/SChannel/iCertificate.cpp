#include <Windows.h>
#include "tCertificate.h"

ICertificate* ICertificate::create()
{
  ICertificate* pObject = NULL;
  try
  {
    pObject = new TCertificate;
  }
  catch(...)
  {
    return NULL;
  }
  return pObject;
}

ICertificate* ICertificate::createInstance()
{
  return new TCertificate;
}

ICertificate::~ICertificate()
{
}