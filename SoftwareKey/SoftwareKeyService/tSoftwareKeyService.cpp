#include <strstream>
#include "tSoftwareKeyService.h"

#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "tSoftwareKey.h"

#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/iLog.h"

#include "../SChannel/iSocket.h"
#include "../SChannel/iCertificate.h"
#include "../SChannel/iSecurityChannel.h"
#include "../SChannel/iSecurityChannelStream.h"

TSoftwareKeyService* TSoftwareKeyService::m_pInstance = NULL;

TSoftwareKeyService::TSoftwareKeyService()
  : m_svcStatusHandle(NULL),
    m_hSvcStopEvent(NULL)
{
  ::memset(&m_svcStatus, 0 , sizeof(m_svcStatus));
}

TSoftwareKeyService::~TSoftwareKeyService()
{
}

TSoftwareKeyService& TSoftwareKeyService::instance()
{
  if(!m_pInstance)
  {
    m_pInstance = new TSoftwareKeyService;
  }
  return *m_pInstance;
}

bool TSoftwareKeyService::deleteInstance()
{
  if(m_pInstance)
  {
    delete m_pInstance;
    m_pInstance = NULL;
    return true;
  }
  return false;
}

int TSoftwareKeyService::startSynced()
{
  std::vector<char> vBuf(c_strServiceName.begin(), c_strServiceName.end());
  vBuf.push_back(0);
  SERVICE_TABLE_ENTRY dispatchTable[] = 
  { 
    { &vBuf.front(), (LPSERVICE_MAIN_FUNCTION)main }, 
    { NULL, NULL }
  }; 
 
  // This call returns when the service has stopped. 
  BOOL fResult = ::StartServiceCtrlDispatcher(dispatchTable);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    logSvcError("Error in ::StartServiceCtrlDispatcher()", nResult);
    return nResult;
  }

  return 0;
}

int TSoftwareKeyService::start()
{
  SC_HANDLE hSCManager = ::OpenSCManager(
    NULL, 
    NULL, 
    SC_MANAGER_CONNECT);
  if(!hSCManager) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::OpenSCManager()", nResult);
    return nResult;
  }

  SC_HANDLE hService = ::OpenService(
    hSCManager, 
    c_strServiceName.c_str(), 
    SERVICE_START);
  if(!hService) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::OpenSCManager()", nResult);
    ::CloseServiceHandle(hSCManager);
    return nResult;
  }

  int nResult = 0;
  BOOL fResult = ::StartService(
    hService,
    0,
    NULL);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::StartService()", nResult);
  }
  else
  {
    ILog("Service started successfully"); 
  }

  ::CloseServiceHandle(hService);
  ::CloseServiceHandle(hSCManager);
  return nResult;
}

int TSoftwareKeyService::stop()
{
  SC_HANDLE hSCManager = ::OpenSCManager(
    NULL, 
    NULL, 
    SC_MANAGER_CONNECT);
  if(!hSCManager) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::OpenSCManager()", nResult);
    return nResult;
  }

  SC_HANDLE hService = ::OpenService(
    hSCManager, 
    c_strServiceName.c_str(), 
    SERVICE_STOP);
  if(!hService) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::OpenSCManager()", nResult);
    ::CloseServiceHandle(hSCManager);
    return nResult;
  }

  int nResult = 0;
  SERVICE_STATUS svcStatus = {0};
  BOOL fResult = ::ControlService(
    hService,
    SERVICE_CONTROL_STOP,
    &svcStatus);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::ControlService()", nResult);
  }
  else
  {
    ILog("Service stopped successfully"); 
  }

  ::CloseServiceHandle(hService);
  ::CloseServiceHandle(hSCManager);
  return nResult;
}

int TSoftwareKeyService::install()
{
  TCHAR szPath[MAX_PATH];
  BOOL fResult = ::GetModuleFileName(NULL, szPath, MAX_PATH);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::GetModuleFileName()", nResult);
    return nResult;
  }

  SC_HANDLE schSCManager = ::OpenSCManager( 
    NULL,                    
    NULL,                    
    SC_MANAGER_CREATE_SERVICE);  
  if(!schSCManager) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::OpenSCManager()", nResult);
    return nResult;
  }

  // Create the service
  SC_HANDLE schService = ::CreateService( 
      schSCManager,              
      c_strServiceName.c_str(),
      c_strServiceFullName.c_str(),
      SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS,
      SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL,
      szPath,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL);
  if(!schService) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CreateService()", nResult);
    ::CloseServiceHandle(schSCManager);
    return nResult;
  }

  ILog("Service installed successfully"); 

  ::CloseServiceHandle(schService); 
  ::CloseServiceHandle(schSCManager);
  return 0;
}

int TSoftwareKeyService::uninstall()
{
  SC_HANDLE hSCManager = ::OpenSCManager(
    NULL, 
    NULL, 
    SC_MANAGER_ALL_ACCESS);
  if(!hSCManager) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::OpenSCManager()", nResult);
    return nResult;
  }

  SC_HANDLE hService = ::OpenService(
    hSCManager, 
    c_strServiceName.c_str(), 
    SERVICE_STOP | DELETE);
  if(!hService) 
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::OpenSCManager()", nResult);
    ::CloseServiceHandle(hSCManager);
    return nResult;
  }
  
  int nResult = 0;
  BOOL fResult = ::DeleteService(hService);
  if(!fResult)
  {
    nResult = ::GetLastError();
    ILogR("Error in ::DeleteService()", nResult);
  }
  else
  {
    ILog("Service uninstalled successfully"); 
  }

  ::CloseServiceHandle(hService);
  ::CloseServiceHandle(hSCManager);
  return nResult;
}

void TSoftwareKeyService::main(DWORD dwArgc, LPTSTR *lpszArgv)
{
  TSoftwareKeyService& svc = TSoftwareKeyService::instance();
  svc.m_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
  svc.m_svcStatus.dwCurrentState = SERVICE_START_PENDING; 
  svc.m_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  svc.m_svcStatus.dwWin32ExitCode = 0; 
  svc.m_svcStatus.dwServiceSpecificExitCode = 0; 
  svc.m_svcStatus.dwCheckPoint = 0; 
  svc.m_svcStatus.dwWaitHint = 0; 


  svc.m_svcStatusHandle = ::RegisterServiceCtrlHandler(
    c_strServiceName.c_str(), 
    (LPHANDLER_FUNCTION)controlHandler);
  if(!svc.m_svcStatusHandle)
  {
    int nResult = ::GetLastError();
    svc.logSvcError("Error in ::RegisterServiceCtrlHandler()", nResult);
    ISchannelUtils::printError(nResult);
    return;
  }

  int nResult = svc.init(); 
  if(nResult) 
  {
    svc.reportStatus(SERVICE_STOPPED, nResult, 0);
    svc.logSvcError("Cannot init service", nResult);
    return; 
  } 
  
  svc.reportStatus(SERVICE_RUNNING, nResult, 0);

  // start software key
  TSoftwareKey softwareKey;
  nResult = softwareKey.start();
  if(nResult)
  {
    svc.reportStatus(SERVICE_STOPPED, nResult, 0);
    svc.logSvcError("Cannot softwareKey.start", nResult);
    return;
  }

  while(true)
  {
    svc.reportStatus(SERVICE_RUNNING, 0, 0);

    bool fStopped = false;
    softwareKey.waitForStop(
      c_unCheckStopped,
      fStopped);

    DWORD dwResult = ::WaitForSingleObject(
      svc.m_hSvcStopEvent, 
      c_unCheckStopped);
    fStopped = fStopped || (dwResult == WAIT_OBJECT_0);

    if(!fStopped)
      continue;

    // stop software key
    nResult = softwareKey.stop();
    if(nResult)
    {
      svc.logSvcError("Cannot softwareKey.stop", nResult);
    }

    svc.logSvc("Exiting now");
    svc.reportStatus(SERVICE_STOPPED, 0, 0);
    break;
  }

  return; 
}

void TSoftwareKeyService::controlHandler(DWORD adwControl)
{
  TSoftwareKeyService& svc = TSoftwareKeyService::instance();
  switch(adwControl) 
  {  
    case SERVICE_CONTROL_STOP: 
      svc.reportStatus(SERVICE_STOP_PENDING, 0, 0);
      ::SetEvent(svc.m_hSvcStopEvent);
      svc.reportStatus(svc.m_svcStatus.dwCurrentState, 0, 0);
      return;
 
    case SERVICE_CONTROL_INTERROGATE: 
      break; 
 
    default: 
       break;
  } 
}

int TSoftwareKeyService::init()
{
  m_hSvcStopEvent = ::CreateEvent(
    NULL,   
    TRUE, 
    FALSE,
    NULL);
  if(!m_hSvcStopEvent)
  {
    int nResult = ::GetLastError();
    logSvcError("Error in ::CreateEvent()", nResult);
    return nResult;
  }
  return 0;
}

void TSoftwareKeyService::reportStatus(
  DWORD adwStatus,
  DWORD adwErrorCode,
  DWORD adwWaitHint)
{
  static DWORD dwCheckPoint = 1;

  m_svcStatus.dwCurrentState = adwStatus;
  m_svcStatus.dwWin32ExitCode = adwErrorCode;
  m_svcStatus.dwWaitHint = adwWaitHint;

  if(adwStatus == SERVICE_START_PENDING)
    m_svcStatus.dwControlsAccepted = 0;
  else 
    m_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  if((adwStatus == SERVICE_RUNNING) ||
     (adwStatus == SERVICE_STOPPED))
    m_svcStatus.dwCheckPoint = 0;
  else 
    m_svcStatus.dwCheckPoint = dwCheckPoint++;

  ::SetServiceStatus(m_svcStatusHandle, &m_svcStatus);
}

void TSoftwareKeyService::logSvc(
  const std::string& astrText)
{
  logSvc(astrText, EVENTLOG_INFORMATION_TYPE);
}

void TSoftwareKeyService::logSvcError(
  const std::string& astrText,
  int anResult)
{
  std::stringstream strStream;
  strStream << astrText << " = " << std::hex << anResult;
  logSvc(strStream.str(), EVENTLOG_ERROR_TYPE);
}

void TSoftwareKeyService::logSvc(
  const std::string& astrText,
  WORD awLevel)
{
  HANDLE hEventSource = RegisterEventSource(
    NULL, 
    c_strServiceName.c_str());
  if(!hEventSource)
    return;

  LPCTSTR lpszStrings[2] = 
  {
    c_strServiceName.c_str(),
    astrText.c_str()
  };

  ::ReportEvent(
    hEventSource,
    awLevel,
    0,
    0,
    NULL,
    2,
    0,
    lpszStrings,
    NULL);

  ::DeregisterEventSource(hEventSource);
}