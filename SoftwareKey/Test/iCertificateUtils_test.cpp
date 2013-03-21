#include <Windows.h>
#include <WinCrypt.h>

#include "iCertificateUtils_test.h"

#include "../SChannel/iCertificate.h"
#include "../SChannel/iCertificateUtils.h"

#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/iLog.h"


namespace certificateUtils
{
  void test_iCertificateUtils()
  {
    std::auto_ptr<ICertificate> spCert(
      ICertificate::create());
    if(!spCert.get())
    {
      ILog("Cannot create certificate");
      return;
    }

    TBlob vData(10, 0xf0);
    ILog("Data:");
    ISchannelUtils::printHexDump(vData.size(), &vData[0]);

    TBlob vSigned;
    int nResult = ICertificateUtils::signHashMessage(
      vData,
      *spCert,
      vSigned);
    if(nResult)
    {
      ILogR("Error in signMessage", nResult);
      ISchannelUtils::printError(nResult);
      return;
    }

    ILog("Signed:");
    ISchannelUtils::printHexDump(vSigned.size(), &vSigned[0]);

    nResult = ICertificateUtils::verifyHashMessage(
      vSigned, 
      *spCert,
      vData);
    if(nResult)
    {
      ILogR("Error in verifyMessage", nResult);
      ISchannelUtils::printError(nResult);
      return;
    }

    ILog("Verified data:");
    ISchannelUtils::printHexDump(vData.size(), &vData[0]);

    test_id();
  }

  void test_id()
  {
    ILog("\nIdentification test");
    ISchannelUtils::printError(
      ISchannelUtils::printDevices2());
  }
}