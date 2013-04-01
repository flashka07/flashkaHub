#pragma once
#include "iCertificate.h"

class IApcLog;

class TCertificate : public ICertificate
{
public:
  TCertificate();
  ~TCertificate();

  const CERT_CONTEXT& getCertContext() const;
  const HCERTSTORE& getStoreHandle() const;

  int loadFromFile(
    const std::string& astrFile);

  int loadFromPFX(
    const std::string& astrFile,
    const std::wstring& awstrPassword,
    const std::wstring& awstrCertSubject);

  void closeCert();

private:
  // class data
  CERT_CONTEXT m_certContext;
  // may be temporary
  PCCERT_CONTEXT m_pcCertContext;

  HCERTSTORE m_hCertStore;

  IApcLog* m_pLog;
};