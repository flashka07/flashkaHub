#pragma once
#include "iCertificate.h"

class TCertificate : public ICertificate
{
public:
  TCertificate();
  ~TCertificate();

  const CERT_CONTEXT& getCertContext() const;
  const HCERTSTORE& getStoreHandle() const;

private:
  // class data
  CERT_CONTEXT m_certContext;
  // may be temporary
  PCCERT_CONTEXT m_pcCertContext;

  HCERTSTORE m_hCertStore;
};