#include "iSchannelUtils.h"

#define _WIN32_DCOM
#include <Windows.h>
#include <stdio.h>

// device identification
#include <boost/archive/binary_oarchive.hpp> 
#include <boost/archive/binary_iarchive.hpp> 
#include <boost/iostreams/stream_buffer.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/back_inserter.hpp>

#include "tComputerIdentifier.h"
#include "tInstanceIdentifier.h"
#include "tComputerIdentifierHelper.h"
// end device identification

#include "tCryptProv.h"

#include "iByteStream.h"
#include <strstream>

#include "iLog.h"

void ISchannelUtils::printHexDump(
  size_t aszLength, 
  const void* apBuffer)
{
  const BYTE* buffer = reinterpret_cast<const BYTE*>(apBuffer);
  DWORD i,count,index;
  CHAR rgbDigits[]="0123456789abcdef";
  CHAR rgbLine[100];
  char cbLine;

  for(index = 0; aszLength;
     aszLength -= count, buffer += count, index += count) 
  {
     count = (aszLength > 16) ? 16:aszLength;

     sprintf_s(rgbLine, 100, "%4.4x  ",index);
     cbLine = 6;

     for(i=0;i<count;i++) 
     {
        rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
        rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
        if(i == 7) 
        {
           rgbLine[cbLine++] = ':';
        } 
        else 
        {
           rgbLine[cbLine++] = ' ';
        }
     }
     for(; i < 16; i++) 
     {
        rgbLine[cbLine++] = ' ';
        rgbLine[cbLine++] = ' ';
        rgbLine[cbLine++] = ' ';
     }

     rgbLine[cbLine++] = ' ';

     for(i = 0; i < count; i++) 
     {
        if(buffer[i] < 32 || buffer[i] > 126) 
        {
           rgbLine[cbLine++] = '.';
        } 
        else 
        {
           rgbLine[cbLine++] = buffer[i];
        }
     }

     rgbLine[cbLine++] = 0;
     printf("%s\n", rgbLine);
  }
}

void ISchannelUtils::printError(
  int anErrorCode)
{
  LPTSTR errorText = NULL;

  ::FormatMessage(
     FORMAT_MESSAGE_FROM_SYSTEM
      | FORMAT_MESSAGE_ALLOCATE_BUFFER
      | FORMAT_MESSAGE_IGNORE_INSERTS,  
     NULL,
     anErrorCode,
     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
     (LPTSTR)&errorText,
     0,
     NULL);

  if(errorText)
  {
    ILog(errorText);
    ::LocalFree(errorText);
    errorText = NULL;
  }
}

// serialize template
// not in class! (must be private)
template<class _Id>
int serializeId(
  const _Id& aId,
  TBlob& aSerialized)
{
  aSerialized.clear();
  
  typedef std::vector<char> TypeBuffer;
  TypeBuffer buf;

  try
  {
    boost::iostreams::back_insert_device<TypeBuffer> serialDevice(buf);
    boost::iostreams::stream<
      boost::iostreams::back_insert_device<TypeBuffer>
      > serialStream(serialDevice);
  
    boost::archive::binary_oarchive ar(serialStream);
    ar << aId; 
    serialStream.flush();
  
    aSerialized.resize(buf.size());
    std::copy(
      buf.begin(),
      buf.end(),
      aSerialized.begin());
  }
  catch(boost::exception&)
  {
    ILog("Error while serializing");
    return -10;
  }

  return 0;
}

// restore template
// not in class! (must be private)
template<class _Id>
int restoreId(
  const TBlob& aSerialized,
  _Id& aId)
{
  typedef std::vector<char> TypeBuffer;
  TypeBuffer buf;

  try
  {
    buf.resize(aSerialized.size());
    std::copy(
      aSerialized.begin(),
      aSerialized.end(),
      buf.begin());

    boost::iostreams::basic_array_source<char> source(&buf[0], buf.size());
    boost::iostreams::stream<
      boost::iostreams::basic_array_source<char>
      > serialStream(source);
    boost::archive::binary_iarchive ar(serialStream);
    ar >> aId; 
  }
  catch(boost::exception&)
  {
    ILog("Error while restoring");
    return -11;
  }

  return 0;
}

int ISchannelUtils::generateComputerID(
  TComputerIdentifier& aId)
{
  HRESULT hRes = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);

  hRes = ::CoInitializeSecurity(
    NULL,
    -1,
    NULL,
    NULL,
    RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    NULL,
    EOAC_NONE,
    NULL);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoInitializeSecurity", hRes);
    return hRes;
  }

  IWbemLocator* pLoc = NULL;
  hRes = ::CoCreateInstance(
    CLSID_WbemLocator, 
    0, 
    CLSCTX_INPROC_SERVER, 
    IID_IWbemLocator, 
    (LPVOID*)&pLoc);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoCreateInstance", hRes);
    return hRes;
  }

  IWbemServices *pSvc = NULL;
  hRes = pLoc->ConnectServer(
    BSTR(L"ROOT\\CIMV2"), 
    NULL,
    NULL, 
    0, 
    NULL, 
    0, 
    0, 
    &pSvc);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoCreateInstance", hRes);
    pLoc->Release();
    return hRes;
  }

  hRes = ::CoSetProxyBlanket(
    pSvc,
    RPC_C_AUTHN_WINNT,
    RPC_C_AUTHZ_NONE,
    NULL,
    RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    NULL,
    EOAC_NONE);
  if(FAILED(hRes))
  {
    ILogR("Error in ::CoCreateInstance", hRes);
    pSvc->Release();
    pLoc->Release();
    return hRes;
  }

  int nResult = fillMotherBoardInfo(
    *pSvc,
    aId.m_MotherBoard);
  if(nResult)
  {
    ILogR("error in fillMotherBoardInfo", nResult);
    pSvc->Release();
    pLoc->Release();
    return nResult;
  }

  nResult = fillProcessorInfo(
    *pSvc,
    aId.m_vProcessors);
  if(nResult)
  {
    ILogR("error in fillProcessorInfo", nResult);
    pSvc->Release();
    pLoc->Release();
    return nResult;
  }

  nResult = fillHardDiskInfo(
    *pSvc,
    aId.m_vHardDrives);
  if(nResult)
  {
    ILogR("error in fillHardDiskInfo", nResult);
    pSvc->Release();
    pLoc->Release();
    return nResult;
  }

  pSvc->Release();
  pLoc->Release();
  ::CoUninitialize();
  return 0;
}

int ISchannelUtils::serializeComputerId(
  const TComputerIdentifier& aId,
  TBlob& aSerialized)
{
  return serializeId(aId, aSerialized);
}

int ISchannelUtils::restoreComputerId(
  const TBlob& aSerialized,
  TComputerIdentifier& aId)
{
  return restoreId(aSerialized, aId);
}

int ISchannelUtils::generateInstanceID(
  TInstanceIdentifier& aId)
{
  aId.m_dwProcessId = ::GetCurrentProcessId();

  {
    TCHAR Buffer[MAX_PATH];
    DWORD dwLength = ::GetModuleFileName(NULL, Buffer, MAX_PATH);
    if(!dwLength)
    {
      int nResult = ::GetLastError();
      ILogR("Error in ::GetModuleFileName", nResult);
      return nResult;
    }
    aId.m_strProcessName = Buffer;
  }

  {
    HANDLE hFile = ::CreateFile(
      aId.m_strProcessName.c_str(),
      GENERIC_READ,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);
    if(hFile == INVALID_HANDLE_VALUE)
    {
      int nResult = ::GetLastError();
      ILogR("Error in ::CreateFile", nResult);
      return nResult;
    }

    DWORD dwFileSize = ::GetFileSize(hFile, NULL);
    TBlob buffer(dwFileSize);
    BOOL fResult = ::ReadFile(
      hFile,
      &buffer.front(),
      buffer.size(),
      NULL,
      NULL);
    if(!fResult)
    {
      int nResult = ::GetLastError();
      ILogR("Error in ::ReadFile", nResult);
      ::CloseHandle(hFile);
      return nResult;
    }
    ::CloseHandle(hFile);

    int nResult = hashSha1(buffer, aId.m_processHashSum);
    if(nResult)
    {
      ILogR("Error in hashSha1", nResult);
      return nResult;
    }
  }
  
  int nResult = generateComputerID(aId.m_compId);
  if(nResult)
  {
    ILogR("Error in generateComputerID", nResult);
    return nResult;
  }

  return 0;
}

int ISchannelUtils::serializeInstanceId(
  const TInstanceIdentifier& aId,
  TBlob& aSerialized)
{
  return serializeId(aId, aSerialized);
}

int ISchannelUtils::restoreInstanceId(
  const TBlob& aSerialized,
  TInstanceIdentifier& aId)
{
  return restoreId(aSerialized, aId);
}


int ISchannelUtils::hashSha1(
  const TCryptProv& aCryptProv,
  const TBlob& aData,
  TBlob& aHashValue)
{
  HCRYPTHASH hHash = NULL;
  BOOL fResult = ::CryptCreateHash(
    aCryptProv.getHCryptProv(),
    CALG_SHA1,
    NULL,
    0,
    &hHash);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptCreateHash", nResult);
    return nResult;
  }

  fResult = ::CryptHashData(
    hHash,
    &aData.front(),
    aData.size(),
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptHashData", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  DWORD dwHashSize = 0;
  DWORD dwParamSize = sizeof(dwHashSize);
  fResult = ::CryptGetHashParam(
    hHash,
    HP_HASHSIZE,
    (PBYTE)&dwHashSize,
    &dwParamSize,
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::CryptGetHashParam", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  aHashValue.resize(dwHashSize);
  dwParamSize = aHashValue.size();
  fResult = ::CryptGetHashParam(
    hHash,
    HP_HASHVAL,
    &aHashValue.front(),
    &dwParamSize,
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::CryptGetHashParam", nResult);
    ::CryptDestroyHash(hHash);
    return nResult;
  }

  ::CryptDestroyHash(hHash);
  return 0;
}

int ISchannelUtils::hashSha1(
  const TBlob& aData,
  TBlob& aHashValue)
{
  TCryptProv cryptProv(L"hashContainer");
  return hashSha1(cryptProv, aData, aHashValue);
}

int ISchannelUtils::importAES256Key(
  const TCryptProv& aCryptProv,
  const TBlob& aKeyBlob,
  HCRYPTKEY& ahKey)
{
  struct
  {
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE bytes[32];
  } blob;
  blob.hdr.bType = PLAINTEXTKEYBLOB;
  blob.hdr.bVersion = CUR_BLOB_VERSION;
  blob.hdr.aiKeyAlg = CALG_AES_256;
  blob.hdr.reserved = 0;
  blob.dwKeySize = 32;
  ::memcpy(blob.bytes, &aKeyBlob.front(), 32);
  
  HCRYPTKEY hKey = NULL;
  BOOL fResult = ::CryptImportKey(
    aCryptProv.getHCryptProv(),
    (BYTE*)&blob,
    sizeof(blob),
    NULL,
    0,
    &hKey);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::CryptImportKey", nResult);
    return nResult;
  }

  ahKey = hKey;
  return 0;
}

int ISchannelUtils::encryptAES256(
  HCRYPTKEY ahKey,
  const TBlob& aData,
  TBlob& aEncrypted)
{
  // hope that hKey is for AES
  // (may be rename function)
  DWORD dwBlockLen = 0;
  DWORD dwParamLen = sizeof(dwBlockLen);
  BOOL fResult = ::CryptGetKeyParam(
    ahKey,
    KP_BLOCKLEN,
    (BYTE*)&dwBlockLen,
    &dwParamLen,
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptGetKeyParam", nResult);
    return nResult;
  }
  dwBlockLen /= 8;

  /*ALG_ID alg = 0;
  dwParamLen = sizeof(alg);
  fResult = ::CryptGetKeyParam(
    ahKey,
    KP_ALGID,
    (BYTE*)&alg,
    &dwParamLen,
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptGetKeyParam", nResult);
    return nResult;
  }*/

  DWORD dwEncryptedSize = 0;
  fResult = ::CryptEncrypt(
    ahKey,
    NULL,
    TRUE,
    0,
    NULL,
    &dwEncryptedSize,
    aData.size());
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in first ::CryptEncrypt", nResult);
    return nResult;
  }

  TBlob tmp;
  tmp.resize(dwEncryptedSize + dwBlockLen);
  std::copy(aData.begin(), aData.end(), tmp.begin());
  fResult = ::CryptEncrypt(
    ahKey,
    NULL,
    TRUE,
    0,
    &tmp.front(),
    &dwEncryptedSize,
    tmp.size());
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in second ::CryptEncrypt", nResult);
    return nResult;
  }
  tmp.resize(tmp.size() - dwBlockLen);
  aEncrypted.swap(tmp);

  return 0;
}

int ISchannelUtils::encryptAES256(
  const TBlob& aKeyBlob,
  const TBlob& aData,
  TBlob& aEncrypted)
{
  TCryptProv cryptProv(L"AEScrypt");
  HCRYPTKEY hKey = NULL;
  int nResult = importAES256Key(
    cryptProv,
    aKeyBlob,
    hKey);
  if(nResult)
  {
    ILogR("Error in importAES256Key", nResult);
    return nResult;
  }

  nResult = encryptAES256(
    hKey,
    aData,
    aEncrypted);
  ::CryptDestroyKey(hKey);
  return nResult;
}

int ISchannelUtils::decryptAES256(
  HCRYPTKEY ahKey,
  const TBlob& aEncrypted,
  TBlob& aData)
{
  DWORD dwBlockLen = 0;
  DWORD dwParamLen = sizeof(dwBlockLen);
  BOOL fResult = ::CryptGetKeyParam(
    ahKey,
    KP_BLOCKLEN,
    (BYTE*)&dwBlockLen,
    &dwParamLen,
    0);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptGetKeyParam", nResult);
    return nResult;
  }
  dwBlockLen /= 8;

  TBlob vResult(aEncrypted);
  DWORD dwOrigSize = vResult.size();
  fResult = ::CryptDecrypt(
    ahKey,
    NULL,
    FALSE,
    0,
    &vResult.front(),
    &dwOrigSize);
  if(!fResult)
  {
    int nResult = ::GetLastError();
    ILogR("Error in ::CryptDecrypt", nResult);
    return nResult;
  }

  vResult.resize(dwOrigSize);
  aData.swap(vResult);
  return 0;
}

int ISchannelUtils::decryptAES256(
  const TBlob& aKeyBlob,
  const TBlob& aEncrypted,
  TBlob& aData)
{
  TCryptProv cryptProv(L"AEScrypt");
  HCRYPTKEY hKey = NULL;
  int nResult = importAES256Key(
    cryptProv,
    aKeyBlob,
    hKey);
  if(nResult)
  {
    ILogR("Error in importAES256Key", nResult);
    return nResult;
  }
  nResult = decryptAES256(
    hKey,
    aEncrypted,
    aData);
  ::CryptDestroyKey(hKey);
  return nResult;
}

int ISchannelUtils::sendCommand(
  IByteStream& aStream,
  const std::string& astrCommand,
  size_t aszNextDataSize)
{
  // print command "command nextDataSize"
  std::stringstream strstream;
  strstream << astrCommand << " " << aszNextDataSize;
  
  std::string strData(strstream.str());

  TBlob vData(strData.length() + 1);
  vData.assign(
    strData.begin(),
    strData.end());
  vData.push_back(0);

  int nResult = aStream.send(
    &vData.front(),
    vData.size());
  if(nResult)
  {
    ILogR("Error while send", nResult);
    return nResult;
  }

  return 0;
}

int ISchannelUtils::receiveCommand(
  IByteStream& aStream,
  std::string& astrCommand,
  size_t& aszNextDataSize,
  unsigned int aunTimeout)
{
  // buffer size for command
  TBlob vData(100, 0);

  size_t szReceived = 0;
  int nResult = aStream.receive(
    &vData.front(),
    vData.size(),
    szReceived,
    aunTimeout);
  if(nResult)
  {
    ILogR("Error while receive", nResult);
    return nResult;
  }
  if(!szReceived)
  {
    ILog("Timeout while receive command");
    return -31;
  }

  std::string strReceived(vData.begin(), vData.end());
  std::stringstream strstream(strReceived);

  strstream >> astrCommand;
  strstream >> aszNextDataSize;

  return 0;
}

int ISchannelUtils::sendData(
  IByteStream& aStream,
  const TBlob& aData)
{
  int nResult = aStream.send(
    &aData.front(),
    aData.size());
  if(nResult)
  {
    ILogR("Error while send", nResult);
    return nResult;
  }

  return 0;
}

int ISchannelUtils::receiveData(
  IByteStream& aStream,
  TBlob& aDataPredefinedSize,
  unsigned int aunTimeout)
{
  size_t szReceived = 0;
  int nResult = aStream.receive(
    &aDataPredefinedSize.front(),
    aDataPredefinedSize.size(),
    szReceived);
  if(nResult)
  {
    ILogR("Error while receive", nResult);
    return nResult;
  }
  if(!szReceived)
  {
    ILog("Timeout while receive command");
    return -31;
  }

  return 0;
}

std::wstring ISchannelUtils::strToWstr(
  const std::string& astrSource)
{
  std::wstring out(astrSource.length(), 0);
  std::string::const_iterator i = astrSource.begin();
  std::string::const_iterator ie = astrSource.end();
  std::wstring::iterator j = out.begin();

  std::locale loc = std::locale();

  for( ; i!=ie; ++i, ++j)
    *j = std::use_facet<std::ctype<std::wstring::value_type>>(loc).widen(*i);

  return out;
}