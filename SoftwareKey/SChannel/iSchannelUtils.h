#pragma once
#include <string>
#include "tBlob.h"

class TComputerIdentifier;

class __declspec(dllexport) ISchannelUtils
{
public:
  static void printHexDump(
    size_t aszLength, 
    const void* apBuffer);

  static void printError(
    int anErrorCode);

  static int printDevices();

  static int printDevices2();

  static int ComputerIdSerialize(
    const TComputerIdentifier& aId,
    TBlob& aSerialized);

  static std::wstring strToWstr(
    const std::string& astrSource);
};