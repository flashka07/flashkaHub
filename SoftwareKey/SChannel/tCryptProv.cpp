#ifndef UNICODE
#define UNICODE
#endif

#include "tCryptProv.h"

#include "iCertificate.h"

#include "tBlob.h"
#include "iLog.h"

#pragma comment(lib, "crypt32.lib")

TCryptProv::TCryptProv(
  const std::wstring& awstrContainerName,
  const std::wstring& awstrProviderName,
  DWORD adwProviderType)
  : m_hCryptProv(0),
    m_wstrContainerName(awstrContainerName),
    m_wstrProviderName(awstrProviderName),
    m_dwProviderType(adwProviderType),
    m_fNewKeyset(false)
{
  int nResult = init();
  if(nResult)
  {
    ILogR("Error in TCryptProv::init()", nResult);
    throw nResult;
  }
}

TCryptProv::TCryptProv(
  const ICertificate& aCert)
  : m_hCryptProv(0),
    m_wstrContainerName(L""),
    m_wstrProviderName(L""),
    m_dwProviderType(0),
    m_fNewKeyset(false)
{
  int nResult = getInfoFromCert(aCert);
  if(nResult)
  {
    ILogR("Error in TCryptProv::getInfoFromCert()", nResult);
    throw nResult;
  }

  nResult = init();
  if(nResult)
  {
    ILogR("Error in TCryptProv::init()", nResult);
    throw nResult;
  }

  /*HCRYPTPROV hProv = NULL;
  DWORD dwPropSize = sizeof(hProv);
  BOOL fResult = ::CertGetCertificateContextProperty(
    &aCert.getCertContext(),
    CERT_KEY_PROV_HANDLE_PROP_ID,
    &hProv,
    &dwPropSize);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in first ::CertGetCertificateContextProperty", nResult);
    throw nResult;
  }

  m_hCryptProv = hProv;*/
}

TCryptProv::~TCryptProv()
{
  if(m_fNewKeyset)
  {
     BOOL fResult = ::CryptAcquireContext(
      &m_hCryptProv,
      m_wstrContainerName.c_str(),
      m_wstrProviderName.c_str(),
      m_dwProviderType,
      CRYPT_DELETEKEYSET /*| CRYPT_MACHINE_KEYSET*/);
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

const std::wstring& TCryptProv::getProviderName() const
{
  return m_wstrProviderName;
}

DWORD TCryptProv::getProviderType() const
{
  return m_dwProviderType;
}

void TCryptProv::setDeleteKeySet(bool afDelete)
{
  m_fNewKeyset = afDelete;
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
      m_wstrProviderName.c_str(),//MS_ENH_RSA_AES_PROV,//MS_DEF_PROV, // may be another like MS_DEF_RSA_SCHANNEL_PROV
      m_dwProviderType,//PROV_RSA_AES,//PROV_RSA_FULL,
      (fFirstCall ? CRYPT_NEWKEYSET : 0) /*| CRYPT_MACHINE_KEYSET*/);
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

int TCryptProv::getInfoFromCert(const ICertificate& aCert)
{
  DWORD dwPropSize = 0;
  BOOL fResult = ::CertGetCertificateContextProperty(
    &aCert.getCertContext(),
    CERT_KEY_PROV_INFO_PROP_ID,
    NULL,
    &dwPropSize);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::CertGetCertificateContextProperty", nResult);
    return nResult;
  }

  TBlob vKeyProvMem(dwPropSize);
  fResult = ::CertGetCertificateContextProperty(
    &aCert.getCertContext(),
    CERT_KEY_PROV_INFO_PROP_ID,
    &vKeyProvMem[0],
    &dwPropSize);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::CertGetCertificateContextProperty", nResult);
    return nResult;
  }
  CRYPT_KEY_PROV_INFO* pKeyProvInfo = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(
    &vKeyProvMem[0]);

  m_wstrContainerName = pKeyProvInfo->pwszContainerName;
  m_wstrProviderName = pKeyProvInfo->pwszProvName;
  m_dwProviderType = pKeyProvInfo->dwProvType;

  return 0;
}