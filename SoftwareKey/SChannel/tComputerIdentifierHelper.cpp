#include "tComputerIdentifier.h"
#include "tComputerIdentifierHelper.h"

#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"

IApcLog* getLogCI()
{
  return IApcLog::getLog("TComputerIdentifierHelper");
}

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
    __L_BADH(getLogCI(), "Error in aSvc.ExecQuery", hRes);
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
      __L_BADH(getLogCI(), "Error in pEnumerator->Next", hRes);
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
    __L_BADH(getLogCI(), "Error in getWMIProp", nResult);
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
    __L_BADH(getLogCI(), "Error in getWMIProp", nResult);
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
    __L_BADH(getLogCI(), "Error in getWMIProp", nResult);
    return nResult;
  }

  return 0;
}