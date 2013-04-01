#include <Windows.h>
#include <string>

#include "tSoftwareKeyService.h"

#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/iLog.h"
// params constants
const std::string c_strCmdInstall("install");
const std::string c_strCmdUninstall("uninstall");
const std::string c_strCmdStart("start");
const std::string c_strCmdStop("stop");

//#ifdef _DEBUG
  #include "tSoftwareKey.h"
  const std::string c_strCmdDebug("dbg");
  int dbg_start();
//#endif


int main(int argc, TCHAR* argv[])
{
  ::setlocale(LC_CTYPE, ".1251");

  if(argc > 1)
  {
    int nResult = 0;
    const std::string strCommand(argv[1]);
    if(!c_strCmdInstall.compare(strCommand))
    {
      nResult = TSoftwareKeyService::instance().install();
    }
    else if(!c_strCmdUninstall.compare(strCommand))
    {
      nResult = TSoftwareKeyService::instance().uninstall();
    }
    else if(!c_strCmdStop.compare(strCommand))
    {
      nResult = TSoftwareKeyService::instance().stop();
    }
    else if(!c_strCmdStart.compare(strCommand))
    {
      nResult = TSoftwareKeyService::instance().start();
    }
//#ifdef _DEBUG
    else if(!c_strCmdDebug.compare(strCommand))
    {
      nResult = dbg_start();
    }
//#endif

    if(nResult)
    {
      ILogR("Error during " + strCommand, nResult);
    }
    TSoftwareKeyService::deleteInstance();
    ISchannelUtils::printError(nResult);
    return nResult;
  }

  int nResult = TSoftwareKeyService::instance().startSynced();
  if(nResult)
  {
    ILogR("Error in startSynced", nResult);
  }
  TSoftwareKeyService::deleteInstance();
  ISchannelUtils::printError(nResult);
  return nResult;
}

//#ifdef _DEBUG
  int dbg_start()
  {
    // start software key
    TSoftwareKey softwareKey;
    int nResult = softwareKey.start();
    if(nResult)
    {
      ILogR("Cannot softwareKey.start", nResult);
      return nResult;
    }

    std::string strExit;
    while(strExit.compare("exit"))
    {
      std::cin >> strExit;
    }

    // stop software key
    nResult = softwareKey.stop();
    if(nResult)
    {
      ILogR("Cannot softwareKey.stop", nResult);
    }
    return nResult;
  }
//#endif