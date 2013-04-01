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
  if(!spSock.get())
  {
    ILog("Cannot create ISocket");
    return -39;
  }

  int nResult = spSock->listenAndAccept("27015");
  if(nResult)
  {
    ILogR("Error in listenAndAccept", nResult);
    return nResult;
  }
  ILog("> Accepted connection");

  std::auto_ptr<ICertificate> spCert(ICertificate::create());
  if(!spCert.get())
  {
    ILog("Cannot create certificate");
    return -40;
  }
  ILog("> Certificate loaded");

  std::auto_ptr<ISecurityChannel> spSessionServer(
    ISecurityChannel::create());
  if(!spSessionServer.get())
  {
    ILog("Cannot create ISecurityChannel");
    return -41;
  }

  nResult = spSessionServer->authenticate(*spSock, *spCert, true);
  if(nResult)
  {
    ILogR("Error in authenticate", nResult);
    return nResult;
  }
  ILog("> Authentication complete");

  std::auto_ptr<ISecurityChannelStream> spStream(
    ISecurityChannelStream::create());
  if(!spStream.get())
  {
    ILog("Cannot create ISecurityChannelStream");
    return -42;
  }

  nResult = spStream->attach(*spSessionServer);
  if(nResult)
  {
    ILogR("Error in attach", nResult);
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

  ILog("Received message:");
  ILog(cBuffer);

  std::string strMessage(">> Hello to Client!");
  nResult = spStream->send(strMessage.c_str(), strMessage.length() + 1);
  if(nResult)
  {
    ILogR("Error in send", nResult);
    return nResult;
  }
  ILog("Sent message: " + strMessage);

  nResult = spStream->receive(cBuffer, 150, szRecieved);
  if(nResult)
  {
    ILogR("Error in receive", nResult);
    return nResult;
  }
  ILog("> Channel was shutted down");
  return 0;
}

int main()
{
  setlocale(LC_CTYPE, ".1251");
  try
  {
    TLibHolder hDll(::LoadLibraryA("schannel.dll"));

    while(true)
    {
      ISchannelUtils::printError(work());   
    }
  }
  catch(...)
  {
    ILog("@@@ Unhandled exception");
    system("pause");
  }

  return 0;
}