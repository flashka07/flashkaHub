#ifndef UNICODE
#define UNICODE
#endif

#include "tCryptProv.h"

#include "iLog.h"

#pragma comment(lib, "crypt32.lib")

TCryptProv::TCryptProv(
  const std::wstring& astrContainerName)
  :m_hCryptProv(0),
  m_wstrContainerName(astrContainerName),
  m_fNewKeyset(false)
{
  int nResult = init();
  if(nResult)
  {
    ILogR("Error in TCryptProv::init()", nResult);
    throw nResult;
  }
}

TCryptProv::~TCryptProv()
{
  if(m_fNewKeyset)
  {
     BOOL fResult = ::CryptAcquireContext(
      &m_hCryptProv,
      m_wstrContainerName.c_str(),
      MS_ENH_RSA_AES_PROV,//MS_DEF_PROV, // may be another like MS_DEF_RSA_SCHANNEL_PROV
      PROV_RSA_AES,//PROV_RSA_FULL,
      CRYPT_DELETEKEYSET | CRYPT_MACHINE_KEYSET);
    if(!fResult)
    {
      ILogR("Error in ::CryptAcquireContext(CRYPT_DELETEKEYSET)", ::GetLastError());
    }
  }

  ::CryptReleaseContext(m_hCryptProv, 0);
}

HCRYPTPROV TCryptProv::getHCryptProv() const
{
  return m_hCryptProv;
}

const std::wstring& TCryptProv::getContainerName() const
{
  return m_wstrContainerName;
}

TCryptProv::TCryptProv()
{
}

int TCryptProv::init()
{
  HCRYPTPROV hCryptProv = NULL;
  bool fNewKeyset = true;
  int nResult = NTE_EXISTS;
  for(bool fFirstCall = true; 
      nResult == NTE_EXISTS;
      fFirstCall = false)
  {
    fNewKeyset = false;
    nResult = 0;
    BOOL fResult = ::CryptAcquireContext(
      &hCryptProv,
      m_wstrContainerName.c_str(),
      MS_DEF_PROV, // may be another like MS_DEF_RSA_SCHANNEL_PROV
      PROV_RSA_FULL,
      (fFirstCall ? CRYPT_NEWKEYSET : 0) | CRYPT_MACHINE_KEYSET);
    if(!fResult)
    {
      nResult = ::GetLastError();
    }
  }
  if(nResult)
  {
    ILogR("Error in ::CryptAcquireContext", nResult);
    return nResult;
  }

  m_hCryptProv = hCryptProv;
  m_fNewKeyset = fNewKeyset;

  return 0;
}