#pragma once
#include <vector>

typedef unsigned char BYTE;
typedef std::vector<BYTE> TBlob;

class __declspec(dllexport) ICertificateUtils
{
public:
  static int createSelfSignedCert();

  // with memory certstore
  static int createSelfSignedCertMS();

  static int signMessage(
    const TBlob& aMessage,
    TBlob& aSignedMessage);

  static int verifyMessage(
    const TBlob& aSignedMessage,
    TBlob& aMessage);

  static int signHashMessage(
    const TBlob& aMessage,
    TBlob& aSignedMessage);

  static int verifyHashMessage(
    const TBlob& aSignedMessage,
    const TBlob& aMessage);

  static int toPFXFile(
    HCERTSTORE ahCertStore,
    const wchar_t* apPassword,
    const char* apFileName);

  static int toFile(
    const void* apBuffer,
    DWORD adwSize,
    const char* apFileName);
};