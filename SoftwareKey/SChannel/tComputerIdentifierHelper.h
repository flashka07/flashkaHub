#pragma once
#include <Windows.h>
#include <comdef.h>
#include <WbemIdl.h>
#pragma comment(lib, "wbemuuid.lib")

#include <boost/serialization/map.hpp> 
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>


int fillMotherBoardInfo(
  IWbemServices& aSvc,
  TDeviceProps& aMotherBoardProps);

int fillProcessorInfo(
  IWbemServices& aSvc,
  std::vector<TDeviceProps>& aProcessors);

int fillHardDiskInfo(
  IWbemServices& aSvc,
  std::vector<TDeviceProps>& aHardDisks);