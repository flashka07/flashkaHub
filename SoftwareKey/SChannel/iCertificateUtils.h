#pragma once

#include "tBlob.h"

class ICertificate;

class __declspec(dllexport) ICertificateUtils
{
public:
  static int createSelfSignedCert();

  // with memory certstore
  static int createSelfSignedCertMS();

  static int signMessage(
    const TBlob& aMessage,
    const ICertificate& aCert,
    TBlob& aSignedMessage);

  static int verifyMessage(
    const TBlob& aSignedMessage,
    const ICertificate& aCert,
    TBlob& aMessage);

  static int signHashMessage(
    const TBlob& aMessage,
    const ICertificate& aCert,
    TBlob& aSignedMessage);

  static int verifyHashMessage(
    const TBlob& aSignedMessage,
    const ICertificate& aCert,
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