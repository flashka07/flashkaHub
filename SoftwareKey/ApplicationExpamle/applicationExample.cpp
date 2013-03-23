#include "tApplicationExample.h"
#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/iLog.h"

void main()
{
  setlocale(LC_CTYPE, ".1251");
  try
  {
    TApplicationExample app;
    ISchannelUtils::printError(app.work());
  }
  catch(...)
  {
    ILog("@@ Unhandled Exception");
  }
}