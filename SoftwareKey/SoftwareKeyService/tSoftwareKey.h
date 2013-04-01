#pragma once
#include <string>

namespace boost { class thread; }
typedef void* HANDLE;
typedef ULONG_PTR HCRYPTKEY;
class ICertificate;
class TCryptProv;
class TStartsReferee;
class IApcLog;

const std::string c_strListenAddress("localhost");
const std::string c_strListenPort("27015");
const unsigned int c_unAcceptTimeoutMs = 10000;

class TSoftwareKey
{
public:
  TSoftwareKey();
  ~TSoftwareKey();

  int start();
  int stop();

  bool isRunning() const;

  // may be we stopped
  int waitForStop(
    unsigned int aunTimeout,
    bool& afStopped);

  const ICertificate& getCertificate() const;
  HCRYPTKEY getAESKey() const;

private:
  int init();

  static void listenerWork(TSoftwareKey* apThis);
  int listenerWork_impl();

  // class data
  bool m_fStarted;
  HANDLE m_hStartEvent;
  HANDLE m_hStopEvent;

  // use Certificate
  ICertificate* m_pCert;

  TCryptProv* m_pCryptProv;
  HCRYPTKEY m_hAesKey;

  boost::thread* m_pNetListenThread;

  TStartsReferee* m_pStartsRef;
  
  IApcLog* m_pLog;
};