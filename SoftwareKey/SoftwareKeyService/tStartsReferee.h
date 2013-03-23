#pragma once
#include <map>
#include <vector>
#include "../SChannel/tBlob.h"
#include "../SChannel/tComputerIdentifier.h"

class TKeyClient;
typedef TBlob THash;
typedef std::map<THash, TKeyClient*> TKeyClientMap;
typedef std::map<THash, TComputerIdentifier> TCompIdMap;
typedef std::vector<THash> TArrayOfHash;
typedef std::vector<TKeyClient*> TStartQueue;

class TCryptProv;
class TInstanceIdentifier;
class TSoftwareKey;
class ISocket;

// allow or disallow application starts
// store connected
class TStartsReferee
{
public:
  TStartsReferee();
  ~TStartsReferee();

  // try to start client on this socket
  int tryStart(
    const TSoftwareKey& softwareKey,
    ISocket& aSocketToBind);

  int isAbleToStart(
    TKeyClient& keyClient,
    bool& afCanStart);

  bool isAlreadyStarted(
    const THash& aHash) const;

  int shutdownAll();

  int forgive(
    TKeyClient& keyClient,
    bool afForever);

private:
  int hashID(
    const TInstanceIdentifier& aInstId,
    THash& aHash);

  int init();

  // class data
  TCryptProv* m_pCryptProv;

  TStartQueue m_wantToStart;
  TKeyClientMap m_connectedClients;
  TArrayOfHash m_connectedUnique;
  TCompIdMap m_uniqueProcIds;
};