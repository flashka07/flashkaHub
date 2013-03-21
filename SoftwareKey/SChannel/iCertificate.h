#pragma once
#include <WinCrypt.h>
#include <string>

class __declspec(dllexport) ICertificate
{
public:
  static ICertificate* create();
  static ICertificate* createInstance();

  virtual ~ICertificate();

  virtual const CERT_CONTEXT& getCertContext() const = 0;
  virtual const HCERTSTORE& getStoreHandle() const = 0;

  virtual int loadFromFile(
    const std::string& astrFile) = 0;

  virtual int loadFromPFX(
    const std::string& astrFile,
    const std::wstring& awstrPassword,
    const std::wstring& awstrCertSubject) = 0;
};