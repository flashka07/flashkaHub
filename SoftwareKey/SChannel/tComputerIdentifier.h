#pragma once
#include <map>
#include <vector>
namespace boost { namespace serialization { class access; } }
typedef std::map<std::wstring, std::wstring> TDeviceProps;

class __declspec(dllexport) TComputerIdentifier
{
public:
  friend class ISchannelUtils;

  TComputerIdentifier();
  ~TComputerIdentifier();

  bool isEqual(
    const TComputerIdentifier& aAnother) const;

private:
  // boost serialization
  friend class boost::serialization::access;
  template<typename _Archive>
  void serialize(
    _Archive& aArchive,
    const unsigned int aunVersion)
  {
    aArchive & m_MotherBoard;
    aArchive & m_vProcessors;
    aArchive & m_vHardDrives;
  }

  // class data
  TDeviceProps m_MotherBoard;
  std::vector<TDeviceProps> m_vProcessors;
  std::vector<TDeviceProps> m_vHardDrives;
};