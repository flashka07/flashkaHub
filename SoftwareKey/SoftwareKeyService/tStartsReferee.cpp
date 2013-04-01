#include "tStartsReferee.h"
#include "tKeyClient.h"

#include "../SChannel/tInstanceIdentifier.h"
#include "../SChannel/tCryptProv.h"
#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/tCS.h"
#include "../../../../projects/ApcLog/ApcLog/Interfaces/tApcLogMacros.h"

TCS g_csWantToStart;

TStartsReferee::TStartsReferee()
  : m_pCryptProv(new TCryptProv(L"StartsRefContainer")),
    m_pLog(IApcLog::getLog("TStartsReferee"))
{
  int nResult = init();
  if(nResult)
  {
    __L_BADH(m_pLog, "error in init", nResult);
    throw nResult;
  }
}

TStartsReferee::~TStartsReferee()
{
  shutdownAll();

  if(m_pCryptProv)
  {
    delete m_pCryptProv;
    m_pCryptProv = NULL;
  }
}

int TStartsReferee::tryStart(
  const TSoftwareKey& softwareKey,
  ISocket& aSocketToBind)
{
  std::auto_ptr<TKeyClient> spKeyClient(
    new TKeyClient(softwareKey, *this, aSocketToBind));

  int nResult = spKeyClient->beginVerification();
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in beginVerification", nResult);
    return nResult;
  }

  g_csWantToStart.lock();
  m_wantToStart.push_back(spKeyClient.get());
  g_csWantToStart.unlock();

  spKeyClient.release()->setCanStart();
  return 0;
}

int TStartsReferee::isAbleToStart(
  TKeyClient& keyClient,
  bool& afCanStart)
{
  afCanStart = false;

  THash vHash;
  int nResult = hashID(keyClient.getInstId(), vHash);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in hashID", nResult);
    return nResult;
  }

  TCSLockGuard lock(g_csWantToStart);

  // check for unique
  bool fIsUnique = false;
  TCompIdMap::const_iterator iUnique = m_uniqueProcIds.find(
    keyClient.getInstId().m_processHashSum);
  if(iUnique != m_uniqueProcIds.end())
  {
    if(!iUnique->second.isEqual(keyClient.getInstId().getComputerId()))
    {
      __L_TRK(m_pLog, "Unique application on not valid computer");
      return 0;
    }
    fIsUnique = true;
  }

  // check for error (trying connect with not unique PID)
  if(isAlreadyStarted(vHash, keyClient) && fIsUnique)
  {
    __L_TRK(m_pLog, "Client with same compid is already connected");
    return 0;
  }

  nResult = keyClient.waitToStart();
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot wait to start", nResult);
    return nResult;
  }

  // all is good, add to started table
  m_connectedClients[vHash] = &keyClient;
  if(fIsUnique)
    m_connectedUnique.push_back(vHash);

  // delete pointer from queue
  nResult = forgive(keyClient, false);
  if(nResult)
  {
    __L_BADH(m_pLog, "Cannot delete pointer from queue", nResult);
    return nResult;
  }

  afCanStart = true;
  return 0;
}

int TStartsReferee::shutdownAll()
{
  // work with temp to avoid deadlock
  TKeyClientMap tmpMap;
  {
    TCSLockGuard lock(g_csWantToStart);
    tmpMap = m_connectedClients;
  }

  for(TKeyClientMap::const_iterator i = tmpMap.begin();
      i != tmpMap.end();
      ++i)
  {
    // need to shutdown TKeyClient
    i->second->kill();
  }

  for(TStartQueue::const_iterator i = m_wantToStart.begin();
      i != m_wantToStart.end();
      ++i)
  {
    // need to shutdown TKeyClient
    delete *i;
  }

  m_connectedClients.clear();
  m_wantToStart.clear();
  m_connectedUnique.clear();

  return 0;
}

int TStartsReferee::forgive(
  TKeyClient& keyClient,
  bool afForever)
{
  TCSLockGuard lock(g_csWantToStart);
  
  TKeyClient* pFound = NULL;
  for(TStartQueue::const_iterator i=m_wantToStart.begin();
      i != m_wantToStart.end();
      ++i)
  {
    if(*i == &keyClient)
    {
      pFound = *i;
      m_wantToStart.erase(i);
      break;
    }
  }

  if(!afForever)
    return 0;

  // if found and need to delete
  if(pFound)
  {
    delete pFound;
    return 0;
  }

  THash vHash;
  int nResult = hashID(keyClient.getInstId(), vHash);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in hashID", nResult);
    return nResult;
  }

  // find in connected
  TKeyClientMap::const_iterator iCC = m_connectedClients.find(vHash);
  if(iCC != m_connectedClients.end())
  {
    delete iCC->second;
    m_connectedClients.erase(iCC);
  }

  // find in unique connected
  for(TArrayOfHash::const_iterator i=m_connectedUnique.begin();
      i != m_connectedUnique.end();
      ++i)
  {
    if(*i == vHash)
    {
      m_connectedUnique.erase(i);
      break;
    }
  }

  return 0;
}


bool TStartsReferee::isAlreadyStarted(
  const THash& aHash,
  const TKeyClient& keyClient) const
{
  // is not a valid function
  // TODO: normal check for already started apps
  return m_connectedClients.find(aHash) != m_connectedClients.end();
}

int TStartsReferee::hashID(
  const TInstanceIdentifier& aInstId,
  THash& aHash)
{
  TBlob vSerialized;
  int nResult = ISchannelUtils::serializeInstanceId(
    aInstId, 
    vSerialized);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in serializeInstanceId", nResult);
    return nResult;
  }

  nResult = ISchannelUtils::hashSha1(
    *m_pCryptProv,
    vSerialized,
    aHash);
  if(nResult)
  {
    __L_BADH(m_pLog, "Error in hashSha1", nResult);
    return nResult;
  }

  return 0;
}

int TStartsReferee::init()
{
  // load pairs Hash of process - comp id,
  // max clients
  // from file
  return 0;
}

