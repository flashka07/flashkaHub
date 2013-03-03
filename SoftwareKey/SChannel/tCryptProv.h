#pragma once
#include <string>

#include <Windows.h>
#include <WinCrypt.h>

class TCryptProv
{
public:
  TCryptProv(
    const std::wstring& awstrContainerName);
  ~TCryptProv();

  HCRYPTPROV getHCryptProv() const;
  const std::wstring& getContainerName() const;

private:
  TCryptProv();
  int init();

  // class data
  HCRYPTPROV m_hCryptProv;
  std::wstring m_wstrContainerName;
  bool m_fNewKeyset;
};