#include "iSchannelUtils.h"

#define _WIN32_DCOM
#include <Windows.h>
#include <stdio.h>

// device identification
#include <Cfgmgr32.h>
#include <Setupapi.h>
#include <devguid.h>

#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Setupapi.lib")

#include <comdef.h>
#include <WbemIdl.h>
#pragma comment(lib, "wbemuuid.lib")
// end device identification

#include "tBlob.h"
#include "iLog.h"

void ISchannelUtils::printHexDump(
  size_t aszLength, 
  const void* apBuffer)
{
  const BYTE* buffer = reinterpret_cast<const BYTE*>(apBuffer);
  DWORD i,count,index;
  CHAR rgbDigits[]="0123456789abcdef";
  CHAR rgbLine[100];
  char cbLine;

  for(index = 0; aszLength;
     aszLength -= count, buffer += count, index += count) 
  {
     count = (aszLength > 16) ? 16:aszLength;

     sprintf_s(rgbLine, 100, "%4.4x  ",index);
     cbLine = 6;

     for(i=0;i<count;i++) 
     {
        rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
        rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
        if(i == 7) 
        {
           rgbLine[cbLine++] = ':';
        } 
        else 
        {
           rgbLine[cbLine++] = ' ';
        }
     }
     for(; i < 16; i++) 
     {
        rgbLine[cbLine++] = ' ';
        rgbLine[cbLine++] = ' ';
        rgbLine[cbLine++] = ' ';
     }

     rgbLine[cbLine++] = ' ';

     for(i = 0; i < count; i++) 
     {
        if(buffer[i] < 32 || buffer[i] > 126) 
        {
           rgbLine[cbLine++] = '.';
        } 
        else 
        {
           rgbLine[cbLine++] = buffer[i];
        }
     }

     rgbLine[cbLine++] = 0;
     printf("%s\n", rgbLine);
  }
}

void ISchannelUtils::printError(
  int anErrorCode)
{
  LPTSTR errorText = NULL;

  ::FormatMessage(
     FORMAT_MESSAGE_FROM_SYSTEM
      | FORMAT_MESSAGE_ALLOCATE_BUFFER
      | FORMAT_MESSAGE_IGNORE_INSERTS,  
     NULL,
     anErrorCode,
     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
     (LPTSTR)&errorText,
     0,
     NULL);

  if(errorText)
  {
    ILog(errorText);
    ::LocalFree(errorText);
    errorText = NULL;
  }
}

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

#include <map>
typedef std::map<std::wstring, std::wstring> TDeviceProps;

class TComputerIdentifier
{
public:
  friend class ISchannelUtils;

  /*TComputerIdentifier();
  ~TComputerIdentifier();*/

private:
  TDeviceProps m_MotherBoard;
  std::vector<TDeviceProps> m_vProcessors;
  std::vector<TDeviceProps> m_vHardDrives;
};

int getWMIProp(
  IWbemServices& aSvc,
  const std::wstring& awstrObj,
  const std::vector<std::wstring>& avParams,
  std::vector<TDeviceProps>& avDevices)
{
  std::wstring strQuery(L"SELECT * FROM " + awstrObj);
  IEnumWbemClassObject* pEnumerator = NULL;
  HRESULT hRes = aSvc.ExecQuery(
    BSTR(L"WQL"),
    BSTR(strQuery.c_str()),
    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
    NULL,
    &pEnumerator);
  if(FAILED(hRes))
  {
    ILogR("Error in aSvc.ExecQuery", hRes);
    return hRes;
  }

  IWbemClassObject* pclsObj = NULL;
  ULONG uReturn = 0;
  int iDevice = 0;
  while(true)
  {
    hRes = pEnumerator->Next(
      WBEM_INFINITE, 
      1, 
      &pclsObj, 
      &uReturn);
    if(FAILED(hRes))
    {
      ILogR("Error in pEnumerator->Next", hRes);
      return hRes;
    }
    if(!uReturn)
      break;

    avDevices.resize(iDevice + 1);

    for(
      std::vector<std::wstring>::const_iterator iPar = avParams.begin();
      iPar != avParams.end();
      ++iPar)
    {
      VARIANT vaValue;
      hRes = pclsObj->Get((*iPar).c_str(), 0, &vaValue, 0, 0);
      
      avDevices[iDevice][*iPar] = vaValue.bstrVal;
      VariantClear(&vaValue);
    }

    pclsObj->Release();
    ++iDevice;
  }
  pEnumerator->Release();
  return 0;
}

int fillMotherBoardInfo(
  IWbemServices& aSvc,
  TDeviceProps& aMotherBoardProps)
{
  std::vector<std::wstring> vParams;
  vParams.push_back(L"Manufacturer");
  vParams.push_back(L"Model");
  vParams.push_back(L"Product");
  vParams.push_back(L"SerialNumber");
  vParams.push_back(L"Version");

  std::vector<TDeviceProps> vValues;
  int nResult = getWMIProp(
    aSvc,
    L"Win32_BaseBoard",
    vParams,
    vValues);
  if(nResult)
  {
    ILogR("Error in getWMIProp", nResult);
    return nResult;
  }

  aMotherBoardProps.swap(vValues[0]);

  return 0;
}

int fillProcessorInfo(
  IWbemServices& aSvc,
  std::vector<TDeviceProps>& aProcessors)
{
  std::vector<std::wstring> vParams;
  vParams.push_back(L"Name");
  vParams.push_back(L"ProcessorId");
  vParams.push_back(L"UniqueId");
  vParams.push_back(L"Version");

  std::vector<std::wstring> vValues;
  int nResult = getWMIProp(
    aSvc,
    L"Win32_Processor",
    vParams,
    aProcessors);
  if(nResult)
  {
    ILogR("Error in getWMIProp", nResult);
    return nResult;
  }

  return 0;
}

int fillHardDiskInfo(
  IWbemServices& aSvc,
  std::vector<TDeviceProps>& aHardDisks)
{
  std::vector<std::wstring> vParams;
  vParams.push_back(L"Name");
  vParams.push_back(L"Manufacturer");
  vParams.push_back(L"Model");
  vParams.push_back(L"SerialNumber");
  vParams.push_back(L"DeviceID");

  std::vector<std::wstring> vValues;
  int nResult = getWMIProp(
    aSvc,
    L"Win32_DiskDrive",
    vParams,
    aHardDisks);
  if(nResult)
  {
    ILogR("Error in getWMIProp", nResult);
    return nResult;
  }

  return 0;
}

int ISchannelUtils::printDevices2()
{
  HRESULT hRes = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);

  hRes = ::CoInitializeSecurity(
    NULL,
    -1,
    NULL,
    NULL,
    RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    NULL,
    EOAC_NONE,
    NULL);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoInitializeSecurity", hRes);
    return hRes;
  }

  IWbemLocator* pLoc = NULL;
  hRes = ::CoCreateInstance(
    CLSID_WbemLocator, 
    0, 
    CLSCTX_INPROC_SERVER, 
    IID_IWbemLocator, 
    (LPVOID*)&pLoc);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoCreateInstance", hRes);
    return hRes;
  }

  IWbemServices *pSvc = NULL;
  hRes = pLoc->ConnectServer(
    BSTR(L"ROOT\\CIMV2"), 
    NULL,
    NULL, 
    0, 
    NULL, 
    0, 
    0, 
    &pSvc);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoCreateInstance", hRes);
    pLoc->Release();
    return hRes;
  }

  hRes = ::CoSetProxyBlanket(
    pSvc,
    RPC_C_AUTHN_WINNT,
    RPC_C_AUTHZ_NONE,
    NULL,
    RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    NULL,
    EOAC_NONE);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoCreateInstance", hRes);
    pSvc->Release();
    pLoc->Release();
    return hRes;
  }

  TComputerIdentifier compId;

  int nResult = fillMotherBoardInfo(
    *pSvc,
    compId.m_MotherBoard);
  if(nResult)
  {
    ILogR("error in fillMotherBoardInfo", nResult);
    pSvc->Release();
    pLoc->Release();
    return nResult;
  }

  nResult = fillProcessorInfo(
    *pSvc,
    compId.m_vProcessors);
  if(nResult)
  {
    ILogR("error in fillMotherBoardInfo", nResult);
    pSvc->Release();
    pLoc->Release();
    return nResult;
  }

  nResult = fillHardDiskInfo(
    *pSvc,
    compId.m_vHardDrives);
  if(nResult)
  {
    ILogR("error in fillMotherBoardInfo", nResult);
    pSvc->Release();
    pLoc->Release();
    return nResult;
  }
  pSvc->Release();
  pLoc->Release();
  ::CoUninitialize();
  return 0;
}

int serializeWstr(
  const std::wstring& awstrSource,
  TBlob& aSerialized)
{
  aSerialized.reserve(
    aSerialized.size() + awstrSource.length() + 1);

  const BYTE cBeginning = 0x02;
  //aSerialized.push_back(
}

int ISchannelUtils::ComputerIdSerialize(
  const TComputerIdentifier& aId,
  TBlob& aSerialized)
{
  aSerialized.clear();


  return 0;
}

std::wstring ISchannelUtils::strToWstr(
  const std::string& astrSource)
{
  std::wstring out(astrSource.length(), 0);
  std::string::const_iterator i = astrSource.begin();
  std::string::const_iterator ie = astrSource.end();
  std::wstring::iterator j = out.begin();

  std::locale loc = std::locale();

  for( ; i!=ie; ++i, ++j)
    *j = std::use_facet<std::ctype<std::wstring::value_type>>(loc).widen(*i);

  return out;
}