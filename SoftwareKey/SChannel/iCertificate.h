#pragma once
#include <WinCrypt.h>


class __declspec(dllexport) ICertificate
{
public:
  static ICertificate* create();
  static ICertificate* createInstance();

  virtual ~ICertificate();

  virtual const CERT_CONTEXT& getCertContext() const = 0;
  virtual const HCERTSTORE& getStoreHandle() const = 0;
};