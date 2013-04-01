#include <Windows.h>
#include <WinCrypt.h>

#include "iCertificateUtils_test.h"

#include "../SChannel/iCertificate.h"
#include "../SChannel/iCertificateUtils.h"

#include "../SChannel/tComputerIdentifier.h"
#include "../SChannel/tInstanceIdentifier.h"

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
    ILog(ISchannelUtils::printHexDump(vData.size(), &vData[0]));

    TBlob vSigned;
    int nResult = ICertificateUtils::signHashMessage(
      vData,
      *spCert,
      vSigned);
    if(nResult)
    {
      ILogR("Error in signMessage", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }

    ILog("Signed:");
    ILog(ISchannelUtils::printHexDump(vSigned.size(), &vSigned[0]));

    nResult = ICertificateUtils::verifyHashMessage(
      vSigned, 
      *spCert,
      vData);
    if(nResult)
    {
      ILogR("Error in verifyMessage", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }

    ILog("Verified data:");
    ILog(ISchannelUtils::printHexDump(vData.size(), &vData[0]));

    test_computerId();
    test_instanceId();
  }

  void test_computerId()
  {
    ILog("\nComputer identification test");

    TComputerIdentifier compId;
    int nResult = ISchannelUtils::generateComputerID(compId);
    if(nResult)
    {
      ILogR("Error in generateComputerID", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }

    TBlob serialized;
    nResult = ISchannelUtils::serializeComputerId(
      compId,
      serialized);
    if(nResult)
    {
      ILogR("Error in serializeComputerId", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }

    ILog("Serialized data:");
    ILog(ISchannelUtils::printHexDump(serialized.size(), &serialized.front()));

    TComputerIdentifier restoredCompId;
    nResult = ISchannelUtils::restoreComputerId(
      serialized,
      restoredCompId);
    if(nResult)
    {
      ILogR("Error in restoreComputerId", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }
    
    if(compId.isEqual(restoredCompId))
      ILog("Restored successfully")
    else
      ILog("Failed to restore")
  }

  void test_instanceId()
  {
    ILog("\nInstance identification test");

    TInstanceIdentifier instId;
    int nResult = ISchannelUtils::generateInstanceID(instId);
    if(nResult)
    {
      ILogR("Error in generateComputerID", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }

    TBlob serialized;
    nResult = ISchannelUtils::serializeInstanceId(
      instId,
      serialized);
    if(nResult)
    {
      ILogR("Error in serializeComputerId", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }

    ILog("Serialized data:");
    ILog(ISchannelUtils::printHexDump(serialized.size(), &serialized.front()));

    TInstanceIdentifier restoredInstId;
    nResult = ISchannelUtils::restoreInstanceId(
      serialized,
      restoredInstId);
    if(nResult)
    {
      ILogR("Error in restoreComputerId", nResult);
      ILog(ISchannelUtils::printError(nResult));
      return;
    }
    
    if(instId.isEqual(restoredInstId))
      ILog("Restored successfully")
    else
      ILog("Failed to restore")
  }
}