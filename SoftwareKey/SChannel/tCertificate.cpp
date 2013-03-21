#include <Windows.h>
#include <fstream>
#include <iterator>

#include "tCertificate.h"

#include "iSchannelUtils.h"
#include "tCryptProv.h"
#include "tBlob.h"
#include "iLog.h"

TCertificate::TCertificate()
 : m_pcCertContext(NULL),
   m_hCertStore(NULL)
{
  ::memset(&m_certContext, 0, sizeof(m_certContext));

  //// TODO: remove this (temporary)
  //m_hCertStore = ::CertOpenSystemStore(NULL, "MY");
  //if(!m_hCertStore)
  //{
  //  int nResult = ::GetLastError();
  //  ILogR("Error in ::CertOpenSystemStore", nResult);
  //  throw nResult;
  //}

  //m_pcCertContext = ::CertFindCertificateInStore(
  //  m_hCertStore,
  //  X509_ASN_ENCODING,
  //  0,
  //  CERT_FIND_SUBJECT_STR,
  //  L"SelfSigned",//L"i.drozdov",
  //  NULL);
  //if(!m_pcCertContext)
  //{
  //  int nResult = ::GetLastError();
  //  ILogR("Error in ::CertFindCertificateInStore", nResult);
  //  throw nResult;
  //}

  //int nResult = loadFromFile("D:\\server_test.pem");
  int nResult = loadFromPFX(
    "D:\\server_test.certkey.p12",
    L"qwerty",
    L"192.168.2.40");
  if(nResult)
  {
    ILogR("Error in loadFromFile", nResult);
    ISchannelUtils::printError(nResult);
    throw nResult;
  }
}

TCertificate::~TCertificate()
{
  closeCert();
}

const CERT_CONTEXT& TCertificate::getCertContext() const
{
  if(m_pcCertContext)
    return *m_pcCertContext;

  return m_certContext;
}

const HCERTSTORE& TCertificate::getStoreHandle() const
{
  return m_hCertStore;
}

int TCertificate::loadFromFile(
  const std::string& astrFile)
{
  closeCert();

  std::ifstream fileCert(astrFile, std::ios::binary);
  std::string strData;
  fileCert.seekg(0, std::ios::end);   
  strData.reserve(fileCert.tellg());
  fileCert.seekg(0, std::ios::beg);

  strData.assign(
    std::istream_iterator<std::string::value_type>(fileCert),
    std::istream_iterator<std::string::value_type>());
  fileCert.close();

  ILog("Certificate data in file:");
  ILog(strData);

  size_t szCertBlobSize = strData.find("-----BEGIN PRIVATE KEY-----", 0);
  if(szCertBlobSize == std::string::npos)
  {
    szCertBlobSize = strData.length();
  }

  TBlob blobData;
  blobData.assign(strData.begin(), strData.begin() + szCertBlobSize);

  CERT_BLOB certBlob = {0};
  certBlob.cbData = szCertBlobSize;
  certBlob.pbData = &blobData[0];

  HCERTSTORE hCertStore = NULL;
  const CERT_CONTEXT* pCert = NULL;
  BOOL fResult = ::CryptQueryObject(
    CERT_QUERY_OBJECT_BLOB,
    &certBlob,
    CERT_QUERY_CONTENT_FLAG_CERT,
    CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
    0,
    NULL,
    NULL,
    NULL,
    &hCertStore,
    NULL,
    (const void**)&pCert);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CertFindCertificateInStore", nResult);
    return nResult;
  }

  ::CertFreeCertificateContext(pCert);

  return 0;
}

int TCertificate::loadFromPFX(
  const std::string& astrFile,
  const std::wstring& awstrPassword,
  const std::wstring& awstrCertSubject)
{
  TBlob blobData;
  // may be use file-mapping
  std::basic_ifstream<TBlob::value_type> fileCert(
    astrFile, 
    std::ios::binary);
  
  fileCert.seekg(0, std::ios::end);   
  blobData.reserve(static_cast<size_t>(fileCert.tellg()));
  fileCert.seekg(0, std::ios::beg);

  blobData.assign(
    std::istreambuf_iterator<TBlob::value_type>(fileCert),
    std::istreambuf_iterator<TBlob::value_type>());
  fileCert.close();

  /*ILog("Loaded pfx:");
  ISchannelUtils::printHexDump(blobData.size(), &blobData[0]);*/

  CRYPT_DATA_BLOB cryptBlob = {0};
  cryptBlob.cbData = blobData.size();
  cryptBlob.pbData = &blobData[0];

  //DWORD dwMsgAndCertEncodingType = 0;
  //DWORD dwContentType = 0;
  //DWORD dwFormatType = 0;
  // 
  //std::wstring wstrFile(ISchannelUtils::strToWstr(astrFile));
  //BOOL fResult = ::CryptQueryObject(
  //  CERT_QUERY_OBJECT_BLOB,
  //  &cryptBlob,//wstrFile.c_str(),
  //  CERT_QUERY_CONTENT_FLAG_ALL,
  //  CERT_QUERY_FORMAT_FLAG_ALL,
  //  0,
  //  &dwMsgAndCertEncodingType,
  //  &dwContentType,
  //  &dwFormatType,
  //  NULL,
  //  NULL,
  //  NULL);
  //if(!fResult)
  //{
  //  int nResult = ::GetLastError();
  //  ILogR("Error in ::CryptQueryObject", nResult);
  //  return nResult;
  //}

  //dwContentType = CERT_QUERY_CONTENT_PFX_AND_LOAD;

  BOOL fResult = ::PFXIsPFXBlob(&cryptBlob);
  if(!fResult)
  {
    ILog(astrFile + " is not a PFX packet!");
    return -10;
  }

  HCERTSTORE hCertStore = ::PFXImportCertStore(
    &cryptBlob,
    awstrPassword.c_str(),
    /*CRYPT_MACHINE_KEYSET |*/
      CRYPT_EXPORTABLE |
      PKCS12_ALLOW_OVERWRITE_KEY /*|
      PKCS12_IMPORT_SILENT*/);
  if(!hCertStore)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::PFXImportCertStore", nResult);
    return nResult;
  }

  PCCERT_CONTEXT pCertContext = ::CertFindCertificateInStore(
    hCertStore,
    X509_ASN_ENCODING,
    0,
    CERT_FIND_SUBJECT_STR,
    awstrCertSubject.c_str(),
    NULL);
  if(!pCertContext)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CertFindCertificateInStore", nResult);
    ::CertCloseStore(hCertStore, 0);
    return nResult;
  }

  closeCert();
  m_hCertStore = hCertStore;
  m_pcCertContext = pCertContext;

  return 0;
}

void TCertificate::closeCert()
{

  if(m_pcCertContext)
  {
    TCryptProv cryptProv(*this);
    cryptProv.setDeleteKeySet(true);
    ::CertFreeCertificateContext(m_pcCertContext);
  }

  if(m_hCertStore)
    ::CertCloseStore(m_hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
}