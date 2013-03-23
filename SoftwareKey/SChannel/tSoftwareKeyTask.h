#pragma once
#include <string>
#include "tBlob.h"

typedef void* HANDLE;
class TSoftwareKeyConnection;

// class task for using in blocking mode
class TSoftwareKeyTask
{
public:
  // it does not store (copy) any data
  TSoftwareKeyTask(
    const std::string& astrCommand,
    const TBlob& aData,
    TBlob& aResult);
  ~TSoftwareKeyTask();

  // (-1 == INFINITE)
  int waitForComplete(
    int& anCompleteResult,
    unsigned int aunTimeout = -1);

  void setCompleted(int anResultCode);

  const std::string& getCommand() const;
  const TBlob& getSource() const;
  TBlob& getResultBuffer();

private:
  const std::string m_strCommand;
  const TBlob& m_SourceData;
  TBlob& m_ResultData;

  int m_nCompleteResult;
  HANDLE m_hComplete;
};