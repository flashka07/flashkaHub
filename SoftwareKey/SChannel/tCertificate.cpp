#include <Windows.h>
#include "tCertificate.h"

#include "iLog.h"
TCertificate::TCertificate()
 :m_hCertStore(NULL)
{
  ::memset(&m_certContext, 0, sizeof(m_certContext));

  // TODO: remove this (temporary)
  m_hCertStore = ::CertOpenSystemStore(NULL, "MY");
  if(!m_hCertStore)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CertOpenSystemStore", nResult);
    throw nResult;
  }

  m_pcCertContext = ::CertFindCertificateInStore(
    m_hCertStore,
    X509_ASN_ENCODING,
    0,
    CERT_FIND_SUBJECT_STR,
    L"SelfSigned",//L"i.drozdov",
    NULL);
  if(!m_pcCertContext)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CertFindCertificateInStore", nResult);
    throw nResult;
  }

  ::memset(&m_certContext, 0, sizeof(m_certContext));
}

TCertificate::~TCertificate()
{
  if(m_hCertStore)
    ::CertCloseStore(m_hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);

  if(m_pcCertContext)
     ::CertFreeCertificateContext(m_pcCertContext);
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