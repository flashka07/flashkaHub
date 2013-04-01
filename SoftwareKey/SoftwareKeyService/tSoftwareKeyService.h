#pragma once
#include <Windows.h>
#include <string>

const std::string c_strServiceName("ApcSoftwareKey");
const std::string c_strServiceFullName("APACS 3000 Software Key");

const unsigned int c_unCheckStopped = 10000;

class IApcLog;

class TSoftwareKeyService
{
public:
  static TSoftwareKeyService& instance();
  static bool deleteInstance();

  int startSynced();
  int start();
  int stop();
  int install();
  int uninstall();

private:
  TSoftwareKeyService();
  ~TSoftwareKeyService();

  static void main(DWORD dwArgc, LPTSTR *lpszArgv);
  static void controlHandler(DWORD adwControl);

  int init();

  void reportStatus(
    DWORD adwStatus,
    DWORD adwErrorCode,
    DWORD adwWaitHint);

  // log to windows events journal
  void logSvc(
    const std::string& astrText);

  void logSvcError(
    const std::string& astrText,
    int anResult);

  void logSvc(
    const std::string& astrText,
    WORD awLevel);

  // singleton
  static TSoftwareKeyService* m_pInstance;

  // class data
  SERVICE_STATUS m_svcStatus; 
  SERVICE_STATUS_HANDLE m_svcStatusHandle; 
  HANDLE m_hSvcStopEvent;
  
  IApcLog* m_pLog;
};