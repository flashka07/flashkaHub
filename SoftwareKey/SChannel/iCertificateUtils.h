#pragma once

class __declspec(dllexport) ICertificateUtils
{
public:
  static int createSelfSignedCert();

  // with memory certstore
  static int createSelfSignedCertMS();

  static int toPFXFile(
    HCERTSTORE ahCertStore,
    const wchar_t* apPassword,
    const char* apFileName);

  static int toFile(
    const void* apBuffer,
    DWORD adwSize,
    const char* apFileName);
};