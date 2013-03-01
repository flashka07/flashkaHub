#include <Windows.h>

#include "../SChannel/iCertificateUtils.h"

#include "../SChannel/iLog.h"

int main()
{
  ILog("Starting create selfsigned cert");

  int nResult = ICertificateUtils::createSelfSignedCertMS();
  if(nResult)
  {
    ILogR("Error in createSelfSignedCert", nResult);
    return nResult;
  }

  ILog("Success");
  return 0;
}