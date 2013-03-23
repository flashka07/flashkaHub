#include <Cfgmgr32.h>
#include <Setupapi.h>
#include <devguid.h>

#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Setupapi.lib")

int getDevicePropBin(
  HDEVINFO ahDevInfoSet,
  SP_DEVINFO_DATA& adevInfoData,
  DWORD adwProperty,
  std::vector<BYTE>& aBuffer,
  DWORD& adwType)
{
  DWORD dwSize = 0;
  DWORD dwType = 0;
  BOOL fpropResult = ::SetupDiGetDeviceRegistryProperty(
    ahDevInfoSet,
    &adevInfoData,
    adwProperty,
    &dwType,
    NULL,
    0,
    &dwSize);
  if(!fpropResult)
  {
    int nResult = ::GetLastError();
    if(nResult == ERROR_INVALID_DATA)
      return 0;

    if(nResult != ERROR_INSUFFICIENT_BUFFER)
    {
      ILogR("Error in first ::SetupDiGetDeviceRegistryProperty", nResult);
      return nResult;
    }
  }

  aBuffer.resize(dwSize);
  fpropResult = ::SetupDiGetDeviceRegistryProperty(
    ahDevInfoSet,
    &adevInfoData,
    adwProperty,
    &dwType,
    &aBuffer[0],
    aBuffer.size(),
    NULL);
  if(!fpropResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::SetupDiGetDeviceRegistryProperty", nResult);
    return nResult;
  }

  adwType = dwType;
  return 0;
}

std::string getDeviceProp(
  HDEVINFO ahDevInfoSet,
  SP_DEVINFO_DATA& adevInfoData,
  DWORD adwProperty)
{
  TBlob buffer;
  DWORD dwType = 0;
  int nResult = getDevicePropBin(
    ahDevInfoSet,
    adevInfoData,
    adwProperty,
    buffer,
    dwType);
  if(nResult)
  {
    ILogR("Error in getDevicePropBin", nResult);
    ISchannelUtils::printError(nResult);
    return "";
  }

  std::string strResult;
  switch(dwType)
  {
  case REG_DWORD:
    {
      std::stringstream stream;
      stream << std::hex << *reinterpret_cast<DWORD*>(&buffer[0]);
      strResult = stream.str();
    }
    break;
  case REG_SZ:
  case REG_MULTI_SZ:
  default:
    strResult.assign(
      std::vector<BYTE>::iterator(buffer.begin()),
      std::vector<BYTE>::iterator(buffer.end()));
    break;
  }

  return strResult;
}

int getDeviceSerial(
  const std::string& astrDeviceName/*,
  TBlob& aBuffer*/)
{
  BOOL fResult = TRUE;

  HANDLE hDevice = ::CreateFile(
    astrDeviceName.c_str(),
    GENERIC_READ,
    FILE_SHARE_WRITE | FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL);
  if(hDevice == INVALID_HANDLE_VALUE)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CreateFile", nResult);
    return nResult;
  }

  CHANGER_PRODUCT_DATA productData = {0};
  DWORD dwReturnedBytes = 0;
  OVERLAPPED ovResult = {0};
  fResult = ::DeviceIoControl(
    hDevice,
    IOCTL_CHANGER_GET_PRODUCT_DATA ,
    NULL,
    0,
    &productData,
    sizeof(productData),
    &dwReturnedBytes,
    &ovResult);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::DeviceIoControl", nResult);
    return nResult;
  }

  ILog(productData.DeviceType);
  return 0;
}

int printDevicesByClass(
  const GUID& aDevClassGUID,
  const std::vector<DWORD>& avParams)
{
  char cDesc[LINE_LEN] = "";
  BOOL fResult = ::SetupDiGetClassDescription(
    &aDevClassGUID,
    cDesc,
    LINE_LEN,
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::SetupDiGetClassDescription", nResult);
    return nResult;
  }

  ILog(std::string("> Device class: ") + cDesc);

  HDEVINFO hDevInfo = ::SetupDiGetClassDevs(
    &aDevClassGUID,
    NULL,
    NULL,
    DIGCF_PRESENT);
  if(hDevInfo == INVALID_HANDLE_VALUE)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::SetupDiGetClassDevs", nResult);
    return nResult;
  }

  for(DWORD i=0; fResult; ++i)
  {
    SP_DEVINFO_DATA devInfoData = {0};
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    fResult = ::SetupDiEnumDeviceInfo(
      hDevInfo,
      i,
      &devInfoData);
    if(!fResult)
    {
      int nResult = ::GetLastError();
      if(nResult != ERROR_NO_MORE_ITEMS)
      {
        ILogR("Error in ::SetupDiEnumDeviceInfo", nResult);
        ISchannelUtils::printError(nResult);
      }
      break;
    }

    //ILog("...");
    for(std::vector<DWORD>::const_iterator iParam = avParams.begin();
      iParam != avParams.end();
      ++iParam)
    {
      ILog(getDeviceProp(hDevInfo, devInfoData, *iParam));
    }

    std::string strDev = getDeviceProp(
      hDevInfo, 
      devInfoData,
      SPDRP_PHYSICAL_DEVICE_OBJECT_NAME);
    getDeviceSerial(strDev);

    // can be unique
    bool fUnique = false;
    {
      TBlob buffer;
      DWORD dwType = 0;
      int nResult = getDevicePropBin(
        hDevInfo, 
        devInfoData, 
        SPDRP_CAPABILITIES, 
        buffer,
        dwType);
      if(nResult)
      {
        ILogR("Error trying to get SPDRP_CAPABILITIES", nResult);
        return nResult;
      }

      DWORD dwCaps = *reinterpret_cast<DWORD*>(&buffer[0]);
      fUnique = (dwCaps & CM_DEVCAP_UNIQUEID) != 0;
    }
    if(fUnique)
      ILog("!!! UNIQUE !!!");
    ILog("...");
  }
    
  ::SetupDiDestroyDeviceInfoList(hDevInfo);
  return 0;
}

int ISchannelUtils::printDevices()
{
  std::vector<GUID> vClasses;

  // get device classes list
  //CONFIGRET crResult = CR_SUCCESS;
  //ULONG ulIndex = 0;
  //GUID guid = {0};
  //while(/*crResult = */::CM_Enumerate_Classes(
  //  ulIndex,
  //  &guid,
  //  0) == CR_SUCCESS)
  //{
  //  vClasses.push_back(guid);
  //  ++ulIndex;
  //}

  vClasses.push_back(GUID_DEVCLASS_SYSTEM);
  /*vClasses.push_back(GUID_DEVCLASS_PROCESSOR);
  vClasses.push_back(GUID_DEVCLASS_DISKDRIVE);
  vClasses.push_back(GUID_DEVCLASS_FIRMWARE);*/


  std::vector<DWORD> vParams;
  vParams.push_back(SPDRP_FRIENDLYNAME);
  vParams.push_back(SPDRP_DEVICEDESC);
  /*vParams.push_back(SPDRP_HARDWAREID);
  vParams.push_back(SPDRP_PHYSICAL_DEVICE_OBJECT_NAME);
  vParams.push_back(SPDRP_ADDRESS);*/

  for(std::vector<GUID>::const_iterator iClass = vClasses.begin();
      iClass != vClasses.end();
      ++iClass)
  {
    int nResult = printDevicesByClass(*iClass, vParams);
    if(nResult)
    {
      ILogR("Error in printDevicesByClass", nResult);
      ISchannelUtils::printError(nResult);
      continue;
    }
  }

  return 0;
}