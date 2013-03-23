#pragma once
#include <Windows.h> // for ULONG_PTR
#include <string>
#include "tBlob.h"

typedef ULONG_PTR HCRYPTKEY;
class TComputerIdentifier;
class TInstanceIdentifier;
class TCryptProv;
class IByteStream;

class __declspec(dllexport) ISchannelUtils
{
public:
  static void printHexDump(
    size_t aszLength, 
    const void* apBuffer);

  static void printError(
    int anErrorCode);

  // identify functions
  static int generateComputerID(
    TComputerIdentifier& aId);

  static int serializeComputerId(
    const TComputerIdentifier& aId,
    TBlob& aSerialized);

  static int restoreComputerId(
    const TBlob& aSerialized,
    TComputerIdentifier& aId);

  static int generateInstanceID(
    TInstanceIdentifier& aId);

  static int serializeInstanceId(
    const TInstanceIdentifier& aId,
    TBlob& aSerialized);

  static int restoreInstanceId(
    const TBlob& aSerialized,
    TInstanceIdentifier& aId);

  // Generate SHA-1 Hash sum
  static int hashSha1(
    const TCryptProv& aCryptProv,
    const TBlob& aData,
    TBlob& aHashValue);

  static int hashSha1(
    const TBlob& aData,
    TBlob& aHashValue);

  // Import AES-256 key
  static int importAES256Key(
    const TCryptProv& aCryptProv,
    const TBlob& aKeyBlob,
    HCRYPTKEY& ahKey);

  // Encrypt with AES-256
  static int encryptAES256(
    HCRYPTKEY ahKey,
    const TBlob& aData,
    TBlob& aEncrypted);

  static int encryptAES256(
    const TBlob& aKeyBlob,
    const TBlob& aData,
    TBlob& aEncrypted);

  // Decrypt with AES-256
  static int decryptAES256(
    HCRYPTKEY ahKey,
    const TBlob& aEncrypted,
    TBlob& aData);

  static int decryptAES256(
    const TBlob& aKeyBlob,
    const TBlob& aEncrypted,
    TBlob& aData);


  // send command via IByteStream
  static int sendCommand(
    IByteStream& aStream,
    const std::string& astrCommand,
    size_t aszNextDataSize);

  // receive command via IByteStream
  static int receiveCommand(
    IByteStream& aStream,
    std::string& astrCommand,
    size_t& aszNextDataSize,
    unsigned int aunTimeout = 0);

  // send data via IByteStream
  static int sendData(
    IByteStream& aStream,
    const TBlob& aData);

  // receive data via IByteStream
  // (aData size must be predefined)
  static int receiveData(
    IByteStream& aStream,
    TBlob& aDataPredefinedSize,
    unsigned int aunTimeout = 0);

  static std::wstring strToWstr(
    const std::string& astrSource);
};