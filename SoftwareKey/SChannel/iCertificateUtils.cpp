#ifndef UNICODE
#define UNICODE
#endif

#include <Windows.h>
#include <WinCrypt.h>
#include <fstream>

#include "iCertificateUtils.h"

#include "tCryptProv.h"
#include "iCertificate.h"

#include "iLog.h"

#pragma comment(lib, "crypt32.lib")

// TODO: CHECK FOR MEMLEAKS

int ICertificateUtils::createSelfSignedCert()
{
  // acquire crypt context
  TCryptProv cryptProv(L"Test Key Container Name");

  int nResult = 0;
  BOOL fResult = TRUE;

  // open MY Cert Store
  HANDLE hCertStore = ::CertOpenStore(
    CERT_STORE_PROV_SYSTEM,
    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    cryptProv.getHCryptProv(), //NULL, // MSDN:  Passing NULL for this parameter causes 
                        // an appropriate, default provider to be used. 
                        // Using the default provider is recommended.
    CERT_SYSTEM_STORE_LOCAL_MACHINE
      | CERT_STORE_NO_CRYPT_RELEASE_FLAG
      | CERT_STORE_OPEN_EXISTING_FLAG,
    L"MY");
  if(!hCertStore)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertOpenStore", nResult);
    return nResult;
  }
  
  // encrypt common name
  std::wstring wstrCommonName(L"CN=Test SelfSigned Cert");
  CERT_NAME_BLOB certNameBlob = {0};
  {
    fResult = ::CertStrToName(
      X509_ASN_ENCODING,
      wstrCommonName.c_str(),
      CERT_OID_NAME_STR,
      NULL,
      NULL,
      &certNameBlob.cbData,
      NULL);
    if(!fResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in first ::CertStrToName", nResult);
      ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
      return nResult;
    }

    certNameBlob.pbData = new BYTE[certNameBlob.cbData];
    fResult = ::CertStrToName(
      X509_ASN_ENCODING,
      wstrCommonName.c_str(),
      CERT_OID_NAME_STR,
      NULL,
      certNameBlob.pbData,
      &certNameBlob.cbData,
      NULL);
    if(!fResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in second ::CertStrToName", nResult);
      ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
      return nResult;
    }
  }

  // find existing certificate
  PCCERT_CONTEXT pCertContext = ::CertFindCertificateInStore(
    hCertStore,
    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    0,
    CERT_FIND_SUBJECT_NAME,
    &certNameBlob,
    NULL);
  if(pCertContext)
  {
    ILog("Certificate found, deleting it...");
    fResult = ::CertDeleteCertificateFromStore(pCertContext);
    if(!fResult)
    {
      nResult = ::GetLastError();
      ILogR(
        "Error in ::CertDeleteCertificateFromStore", 
        nResult);
      ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
      return nResult;
    }
    pCertContext = NULL;
  }
  
  // generate keys
  DWORD dwKeyLength = 0x08000000;
  HCRYPTKEY hCryptKey = NULL;
  fResult = ::CryptGenKey(
    cryptProv.getHCryptProv(),
    AT_KEYEXCHANGE,
    /*dwKeyLength | */CRYPT_EXPORTABLE,
    &hCryptKey);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CryptGenKey", nResult);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  // creating the self-signed certificate
  // may be it is not right
  wchar_t wstrContName[500] = L"";
  wcscpy(wstrContName, cryptProv.getContainerName().c_str());
  //::mbstowcs(

  CRYPT_KEY_PROV_INFO keyProvInfo = {0};
  keyProvInfo.pwszContainerName = wstrContName;
  keyProvInfo.pwszProvName = MS_DEF_PROV_W;
  keyProvInfo.dwProvType = PROV_RSA_FULL;
  keyProvInfo.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
  keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

  SYSTEMTIME sysTime;
  ::GetSystemTime(&sysTime);
  sysTime.wYear += 10;

  CERT_EXTENSIONS certExts = {0};
  PCCERT_CONTEXT pSelfSignContext = ::CertCreateSelfSignCertificate(
    cryptProv.getHCryptProv(),
    &certNameBlob,
    0,
    &keyProvInfo,
    NULL,
    NULL,
    &sysTime,
    &certExts);
  if(!pSelfSignContext)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertCreateSelfSignCertificate", nResult);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  // add created certificate to MY store and obtain added (pCertContext)
  fResult = ::CertAddCertificateContextToStore(
    hCertStore,
    pSelfSignContext,
    CERT_STORE_ADD_REPLACE_EXISTING,
    &pCertContext);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertAddCertificateContextToStore", nResult);
    ::CertFreeCertificateContext(pSelfSignContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  ::CertFreeCertificateContext(pSelfSignContext);

  CRYPT_KEY_PROV_INFO keyPISetInfo = {0};
  keyPISetInfo.pwszContainerName = wstrContName;
  keyPISetInfo.pwszProvName = MS_DEF_PROV_W;
  keyPISetInfo.dwProvType = PROV_RSA_FULL;
  keyPISetInfo.dwFlags = CRYPT_MACHINE_KEYSET;
  keyPISetInfo.dwKeySpec = AT_KEYEXCHANGE;

  fResult = ::CertSetCertificateContextProperty(
    pCertContext,
    CERT_KEY_PROV_INFO_PROP_ID,
    0,
    &keyPISetInfo);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertSetCertificateContextProperty", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  // export certificate to PFX file
  nResult = toPFXFile(
    hCertStore,
    L"qwerty",
    "test_cert.pfx");
  if(nResult)
  {
    ILogR("Error in toPFXFile", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  ::CertFreeCertificateContext(pCertContext);
  ::CryptDestroyKey(hCryptKey);
  fResult = ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertCloseStore", nResult);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  return 0;
}

int ICertificateUtils::createSelfSignedCertMS()
{
  // acquire crypt context
  TCryptProv cryptProv(L"Test Key Container Name");
  
  int nResult = 0;
  BOOL fResult = TRUE;

  // open MY Cert Store
  HANDLE hCertStore = ::CertOpenStore(
    CERT_STORE_PROV_MEMORY,
    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    cryptProv.getHCryptProv(), //NULL, // MSDN:  Passing NULL for this parameter causes 
                        // an appropriate, default provider to be used. 
                        // Using the default provider is recommended.
    CERT_SYSTEM_STORE_LOCAL_MACHINE
      | CERT_STORE_NO_CRYPT_RELEASE_FLAG
      | CERT_STORE_OPEN_EXISTING_FLAG,
    NULL);
  if(!hCertStore)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertOpenStore", nResult);
    return nResult;
  }
  
  // encrypt common name
  std::wstring wstrCommonName(L"CN=Test SelfSigned Cert");
  CERT_NAME_BLOB certNameBlob = {0};
  {
    fResult = ::CertStrToName(
      X509_ASN_ENCODING,
      wstrCommonName.c_str(),
      CERT_OID_NAME_STR,
      NULL,
      NULL,
      &certNameBlob.cbData,
      NULL);
    if(!fResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in first ::CertStrToName", nResult);
      ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
      return nResult;
    }

    certNameBlob.pbData = new BYTE[certNameBlob.cbData];
    fResult = ::CertStrToName(
      X509_ASN_ENCODING,
      wstrCommonName.c_str(),
      CERT_OID_NAME_STR,
      NULL,
      certNameBlob.pbData,
      &certNameBlob.cbData,
      NULL);
    if(!fResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in second ::CertStrToName", nResult);
      ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
      return nResult;
    }
  }
  
  // generate keys
  DWORD dwKeyLength = 0x08000000;
  HCRYPTKEY hCryptKey = NULL;
  fResult = ::CryptGenKey(
    cryptProv.getHCryptProv(),
    AT_KEYEXCHANGE,
    /*dwKeyLength | */CRYPT_EXPORTABLE,
    &hCryptKey);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CryptGenKey", nResult);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  // creating the self-signed certificate
  // may be it is not right
  wchar_t wstrContName[500] = L"";
  wcscpy(wstrContName, cryptProv.getContainerName().c_str());
  //::mbstowcs(

  CRYPT_KEY_PROV_INFO keyProvInfo = {0};
  keyProvInfo.pwszContainerName = wstrContName;
  keyProvInfo.pwszProvName = MS_DEF_PROV_W;
  keyProvInfo.dwProvType = PROV_RSA_FULL;
  keyProvInfo.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
  keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

  SYSTEMTIME sysTime;
  ::GetSystemTime(&sysTime);
  sysTime.wYear += 10;

  CERT_EXTENSIONS certExts = {0};
  PCCERT_CONTEXT pSelfSignContext = ::CertCreateSelfSignCertificate(
    cryptProv.getHCryptProv(),
    &certNameBlob,
    0,
    &keyProvInfo,
    NULL,
    NULL,
    &sysTime,
    &certExts);
  if(!pSelfSignContext)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertCreateSelfSignCertificate", nResult);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  // add created certificate to MY store and obtain added (pCertContext)
  PCCERT_CONTEXT pCertContext = NULL;
  fResult = ::CertAddCertificateContextToStore(
    hCertStore,
    pSelfSignContext,
    CERT_STORE_ADD_REPLACE_EXISTING,
    &pCertContext);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertAddCertificateContextToStore", nResult);
    ::CertFreeCertificateContext(pSelfSignContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  ::CertFreeCertificateContext(pSelfSignContext);

   // export certificate to PFX file
  nResult = toPFXFile(
    hCertStore,
    L"qwerty",
    "test_cert.pfx");
  if(nResult)
  {
    ILogR("Error in toPFXFile", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  // export private key
  /*DWORD dwKBufferSize = 0;
  fResult = ::CryptExportKey(
    hCryptKey,
    NULL,
    PRIVATEKEYBLOB,
    0,
    NULL,
    &dwKBufferSize);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in first ::CryptExportKey", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  BYTE* pKBuffer = new BYTE[dwKBufferSize];
  fResult = ::CryptExportKey(
    hCryptKey,
    NULL,
    PRIVATEKEYBLOB,
    0,
    pKBuffer,
    &dwKBufferSize);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in second ::CryptExportKey", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }
  {
    // export private key to string file
    DWORD dwBufferSize = 0;
    fResult = ::CryptBinaryToStringA(
      pKBuffer,
      dwKBufferSize,
      CRYPT_STRING_BASE64HEADER,
      NULL,
      &dwBufferSize);
    if(!fResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in first ::CryptBinaryToStringA", nResult);
      ::CertFreeCertificateContext(pCertContext);
      ::CryptDestroyKey(hCryptKey);
      ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
      return nResult;
    }
    char* pBuffer = new char[dwBufferSize];
    fResult = ::CryptBinaryToStringA(
      pCertContext->pbCertEncoded,
      pCertContext->cbCertEncoded,
      CRYPT_STRING_BASE64HEADER,
      pBuffer,
      &dwBufferSize);
    if(!fResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in second ::CryptBinaryToStringA", nResult);
      ::CertFreeCertificateContext(pCertContext);
      ::CryptDestroyKey(hCryptKey);
      ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
      return nResult;
    }
    delete[] pBuffer;
  }
  delete[] pKBuffer; */

  // export certificate to string file
  DWORD dwBufferSize = 0;
  fResult = ::CryptBinaryToStringA(
    pCertContext->pbCertEncoded,
    pCertContext->cbCertEncoded,
    CRYPT_STRING_BASE64HEADER,
    NULL,
    &dwBufferSize);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in first ::CryptBinaryToStringA", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }
  char* pBuffer = new char[dwBufferSize];
  fResult = ::CryptBinaryToStringA(
    pCertContext->pbCertEncoded,
    pCertContext->cbCertEncoded,
    CRYPT_STRING_BASE64HEADER,
    pBuffer,
    &dwBufferSize);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in second ::CryptBinaryToStringA", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  // stream to file
  nResult = toFile(
    pBuffer, 
    dwBufferSize,
    "test_cert.cer");
  if(nResult)
  {
    ILogR("Error in toFile", nResult);
    ::CertFreeCertificateContext(pCertContext);
    ::CryptDestroyKey(hCryptKey);
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    return nResult;
  }

  ::CertFreeCertificateContext(pCertContext);
  ::CryptDestroyKey(hCryptKey);
  fResult = ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::CertCloseStore", nResult);
    return nResult;
  }

  return 0;
}

int ICertificateUtils::signMessage(
  const TBlob& aMessage,
  const ICertificate& aCert,
  TBlob& aSignedMessage)
{
  CRYPT_SIGN_MESSAGE_PARA signMsgParams = {0};
  signMsgParams.cbSize = sizeof(signMsgParams);
  signMsgParams.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING ;
  signMsgParams.pSigningCert = &aCert.getCertContext();
  signMsgParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;

  const BYTE* arrMessages[] = {&aMessage[0]};
  DWORD sizes[] = {aMessage.size()};
  DWORD dwOutSize = 0;
  BOOL fResult = ::CryptSignMessage(
    &signMsgParams,
    TRUE,
    1,
    arrMessages,
    sizes,
    NULL,
    &dwOutSize);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::CryptSignMessage", nResult);
    return nResult;
  }

  aSignedMessage.resize(dwOutSize);
  fResult = ::CryptSignMessage(
    &signMsgParams,
    TRUE,
    1,
    arrMessages,
    sizes,
    &aSignedMessage[0],
    &dwOutSize);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::CryptSignMessage", nResult);
    return nResult;
  }

  return 0;
}

int ICertificateUtils::verifyMessage(
  const TBlob& aSignedMessage,
  const ICertificate& aCert,
  TBlob& aMessage)
{
  CRYPT_VERIFY_MESSAGE_PARA veriMsgParams = {0};
  veriMsgParams.cbSize = sizeof(veriMsgParams);
  veriMsgParams.dwMsgAndCertEncodingType = X509_ASN_ENCODING 
    | PKCS_7_ASN_ENCODING;

  PCCERT_CONTEXT pCert = NULL;
  DWORD dwOutSize = 0;
  BOOL fResult = ::CryptVerifyMessageSignature(
    &veriMsgParams,
    0,
    &aSignedMessage[0],
    aSignedMessage.size(),
    NULL,
    &dwOutSize,
    &pCert);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::CryptVerifyMessageSignature", nResult);
    return nResult;
  }

  aMessage.resize(dwOutSize);
  fResult = ::CryptVerifyMessageSignature(
    &veriMsgParams,
    0,
    &aSignedMessage[0],
    aSignedMessage.size(),
    &aMessage[0],
    &dwOutSize,
    &pCert);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::CryptVerifyMessageSignature", nResult);
    return nResult;
  }

  return 0;
}

int ICertificateUtils::signHashMessage(
  const TBlob& aMessage,
  const ICertificate& aCert,
  TBlob& aSignedMessage)
{
  TCryptProv cryptProv(aCert);

  HCRYPTHASH hHash = NULL;
  BOOL fResult = ::CryptCreateHash(
    cryptProv.getHCryptProv(),
    CALG_SHA1,
    NULL,
    0,
    &hHash);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptCreateHash", nResult);
    return nResult;
  }

  fResult = ::CryptHashData(
    hHash,
    &aMessage[0],
    aMessage.size(),
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptHashData", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  DWORD dwOutSize = 0;
  fResult = ::CryptSignHash(
    hHash,
    AT_KEYEXCHANGE,
    NULL,
    0,
    NULL,
    &dwOutSize);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::CryptSignHash", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  aSignedMessage.resize(dwOutSize);
  fResult = ::CryptSignHash(
    hHash,
    AT_KEYEXCHANGE,
    NULL,
    0,
    &aSignedMessage[0],
    &dwOutSize);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::CryptSignHash", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  ::CryptDestroyHash(hHash);

  return 0;
}

int ICertificateUtils::verifyHashMessage(
  const TBlob& aSignedMessage,
  const ICertificate& aCert,
  const TBlob& aMessage)
{
  TCryptProv cryptProv(aCert);

  HCRYPTHASH hHash = NULL;
  BOOL fResult = ::CryptCreateHash(
    cryptProv.getHCryptProv(),
    CALG_SHA1,
    NULL,
    0,
    &hHash);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptCreateHash", nResult);
    return nResult;
  }

  fResult = ::CryptHashData(
    hHash,
    &aMessage[0],
    aMessage.size(),
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptHashData", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  // obtain public key
  HCRYPTKEY hPubKey = NULL;
  fResult = ::CryptImportPublicKeyInfo(
    cryptProv.getHCryptProv(),
    X509_ASN_ENCODING,
    &aCert.getCertContext().pCertInfo->SubjectPublicKeyInfo,
    &hPubKey);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptImportPublicKeyInfo", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  fResult = ::CryptVerifySignature(
    hHash,
    &aSignedMessage[0],
    aSignedMessage.size(),
    hPubKey,
    NULL,
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptVerifySignature", nResult);
    ::CryptDestroyKey(hPubKey);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  ::CryptDestroyKey(hPubKey);
  ::CryptDestroyHash(hHash);

  return 0;
}

int ICertificateUtils::toPFXFile(
  HCERTSTORE ahCertStore,
  const wchar_t* apPassword,
  const char* apFileName)
{
  CRYPT_DATA_BLOB blobExport = {0};
  BOOL fResult = ::PFXExportCertStoreEx(
    ahCertStore,
    &blobExport,
    apPassword,
    NULL,
    EXPORT_PRIVATE_KEYS);
  if(!fResult || !blobExport.cbData)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::PFXExportCertStoreEx", nResult);
    return nResult;
  }

  TBlob vBuffer(blobExport.cbData, 0);
  blobExport.pbData = &vBuffer[0];
  fResult = ::PFXExportCertStoreEx(
    ahCertStore,
    &blobExport,
    apPassword,
    NULL,
    EXPORT_PRIVATE_KEYS);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::PFXExportCertStoreEx", nResult);
    return nResult;
  }

  // stream to file
  int nResult = toFile(
    blobExport.pbData, 
    blobExport.cbData,
    apFileName);
  if(nResult)
  {
    ILogR("Error in toFile", nResult);
    return nResult;
  }

  return 0;
}

int ICertificateUtils::toFile(
  const void* apBuffer,
  DWORD adwSize,
  const char* apFileName)
{
  std::ofstream binFile(apFileName, std::ofstream::binary);
  if(!binFile)
  {
    int nResult = binFile.failbit;
    ILogR("Error creating out filestream", nResult);
    return nResult;
  }

  binFile.write(
    (const char*)apBuffer, 
    adwSize);
  if(!binFile)
  {
    int nResult = binFile.failbit;
    ILogR("Error writing into out filestream", nResult);
    return nResult;
  }

  return 0;
}