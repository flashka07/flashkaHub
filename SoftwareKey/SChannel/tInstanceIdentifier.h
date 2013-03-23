#pragma once
#include <string>
#include "tComputerIdentifier.h"

typedef unsigned long DWORD;
#include "tBlob.h"

class __declspec(dllexport) TInstanceIdentifier
{
  public:
  friend class ISchannelUtils;
  friend class TStartsReferee;

  TInstanceIdentifier();
  ~TInstanceIdentifier();

  bool isEqual(
    const TInstanceIdentifier& aAnother) const;

  const TComputerIdentifier& getComputerId() const;

private:
  // boost serialization
  friend class boost::serialization::access;
  template<typename _Archive>
  void serialize(
    _Archive& aArchive,
    const unsigned int aunVersion)
  {
    aArchive & m_compId;
    aArchive & m_dwProcessId;
    aArchive & m_strProcessName;
    aArchive & m_processHashSum;
  }

  // class data
  TComputerIdentifier m_compId;
  DWORD m_dwProcessId;
  std::string m_strProcessName;
  TBlob m_processHashSum;
};