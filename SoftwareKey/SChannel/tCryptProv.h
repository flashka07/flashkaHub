#pragma once
#include <string>

#include <Windows.h>
#include <WinCrypt.h>

class ICertificate;
class IApcLog;

class __declspec(dllexport) TCryptProv
{
public:
  TCryptProv(
    const std::wstring& awstrContainerName,
    const std::wstring& awstrProviderName = MS_ENH_RSA_AES_PROV_W,
    DWORD adwProviderType = PROV_RSA_AES);
  TCryptProv(
    const ICertificate& aCert);
  ~TCryptProv();

  HCRYPTPROV getHCryptProv() const;
  const std::wstring& getContainerName() const;
  const std::wstring& getProviderName() const;
  DWORD getProviderType() const;

  void setDeleteKeySet(bool afDelete);

private:
  TCryptProv();
  int init();
  int getInfoFromCert(const ICertificate& aCert);

  // class data
  HCRYPTPROV m_hCryptProv;
  std::wstring m_wstrContainerName;
  std::wstring m_wstrProviderName;
  DWORD m_dwProviderType;
  bool m_fNewKeyset;
  
  IApcLog* m_pLog;
};