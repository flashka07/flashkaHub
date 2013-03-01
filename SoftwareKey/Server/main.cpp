#include <iostream>
#include <memory>

#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include "../SChannel/iSocket.h"
#include "../SChannel/iCertificate.h"
#include "../SChannel/iSchannelSessionServer.h"
#include "../SChannel/iSecurityChannelStream.h"

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

int main()
{
  try
  {
    TLibHolder hDll(::LoadLibraryA("schannel.dll"));

    while(true)
    {
      std::auto_ptr<ISocket> spSock(ISocket::create());
      int nResult = spSock->listenAndAccept("27015");
      if(nResult)
      {
        ILogR("Error in listenAndAccept", nResult);
        return nResult;
      }

      std::auto_ptr<ICertificate> spCert(ICertificate::create());

      std::auto_ptr<ISchannelSessionServer> spSessionServer(
        ISchannelSessionServer::create());

      nResult = spSessionServer->authenticate(*spSock, *spCert);
      if(nResult)
      {
        ILogR("Error in authenticate", nResult);
        continue;
      }

      std::auto_ptr<ISecurityChannelStream> spStream(
        ISecurityChannelStream::create());
      nResult = spStream->attach(*spSessionServer);
      if(nResult)
      {
        ILogR("Error in attach", nResult);
        continue;
      }

      char cBuffer[150] = "";
      size_t szRecieved = 0;
      nResult = spStream->receive(cBuffer, 150, szRecieved);
      if(nResult)
      {
        ILogR("Error in receive", nResult);
        continue;
      }

      ILog(cBuffer);

      std::string strMessage(">> Hello to Client!");
      nResult = spStream->send(strMessage.c_str(), strMessage.length() + 1);
      if(nResult)
      {
        ILogR("Error in send", nResult);
        continue;
      }

      nResult = spStream->receive(cBuffer, 150, szRecieved);
      if(nResult)
      {
        ILogR("Error in receive", nResult);
        continue;
      }
    }
  }
  catch(...)
  {
    ILog("@@@ Unhandled exception");
  }

  return 0;
}