#pragma once
#include "../SChannel/iSoftwareKeyPingRP.h"

class ISoftwareKeyConnection;
class ICertificate;
class IApcLog;

class TApplicationExample : public ISoftwareKeyPingRP
{
public:
  TApplicationExample();
  ~TApplicationExample();

  int work();

  // ISoftwareKeyPingRP
  void onPingFail();

private:
  void cleanup();

  // class data
  ISoftwareKeyConnection* m_pKey;
  ICertificate* m_pCert;

  IApcLog* m_pLog;
};