#include <iostream>
#include <memory>

#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "../SChannel/iSocket.h"
#include "../SChannel/iCertificate.h"
#include "../SChannel/iSecurityChannel.h"
#include "../SChannel/iSecurityChannelStream.h"

#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/iLog.h"

class TLibHolder
{
public:
  TLibHolder(HMODULE hModule) : m_hModule(hModule)
  {
  }
  ~TLibHolder()
  {
    if(m_hModule)
      ::FreeLibrary(m_hModule);
  }
private:
  HMODULE m_hModule;
};

int work()
{
  std::auto_ptr<ISocket> spSock(ISocket::create());
  int nResult = spSock->connect("localhost", "27015");
  if(nResult)
  {
    ILogR("Error in listenAndAccept", nResult);
    return nResult;
  }
  ILog("> Connected to server");

  std::auto_ptr<ICertificate> spCert(ICertificate::create());

  /*std::auto_ptr<ISchannelSessionClient> spSessionClient(
    ISchannelSessionClient::create());*/
  std::auto_ptr<ISecurityChannel> spSessionClient(
    ISecurityChannel::create());

  nResult = spSessionClient->authenticate(*spSock, *spCert);
  if(nResult)
  {
    ILogR("Error in authenticate", nResult);
    return nResult;
  }

  std::auto_ptr<ISecurityChannelStream> spStream(
    ISecurityChannelStream::create());
  nResult = spStream->attach(*spSessionClient);
  if(nResult)
  {
    ILogR("Error in attach", nResult);
    return nResult;
  }

  std::string strMessage(">> Hello to Server!");
  nResult = spStream->send(strMessage.c_str(), strMessage.length() + 1);
  if(nResult)
  {
    ILogR("Error in send", nResult);
    return nResult;
  }

  char cBuffer[150] = "";
  size_t szRecieved = 0;
  nResult = spStream->receive(cBuffer, 150, szRecieved);
  if(nResult)
  {
    ILogR("Error in receive", nResult);
    return nResult;
  }

  ILog(cBuffer);

  nResult = spSessionClient->shutdown(true);
  if(nResult)
  {
    ILogR("Error in shutdown", nResult);
    return nResult;
  }
  return 0;
}

int main()
{
  setlocale(LC_CTYPE, ".1251");
  try
  {
    TLibHolder hDll(::LoadLibraryA("schannel.dll"));

    ISchannelUtils::printError(work());    
  }
  catch(...)
  {
    ILog("@@@ Unhandled exception");
    system("pause");
  }

  return 0;
}