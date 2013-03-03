#include <Windows.h>
#include <WinCrypt.h>

#include "iCertificateUtils_test.h"

#include "../SChannel/iCertificateUtils.h"

#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/iLog.h"


namespace certificateUtils
{
  void test_iCertificateUtils()
  {
    TBlob vData(10, 0xf0);
    ILog("Data:");
    ISchannelUtils::printHexDump(vData.size(), &vData[0]);

    TBlob vSigned;
    int nResult = ICertificateUtils::signHashMessage(
      vData,
      vSigned);
    if(nResult)
    {
      ILogR("Error in signMessage", nResult);
      return;
    }

    ILog("Signed:");
    ISchannelUtils::printHexDump(vSigned.size(), &vSigned[0]);

    //vData.clear();

    nResult = ICertificateUtils::verifyHashMessage(vSigned, vData);
    if(nResult)
    {
      ILogR("Error in verifyMessage", nResult);
      return;
    }

    ILog("Verified data:");
    ISchannelUtils::printHexDump(vData.size(), &vData[0]);
  }
}