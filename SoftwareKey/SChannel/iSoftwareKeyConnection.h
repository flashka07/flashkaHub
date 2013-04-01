#pragma once
#include "tBlob.h"

class ISoftwareKeyPingRP;
class ICertificate;

// class for connection with software key
class __declspec(dllexport) ISoftwareKeyConnection
{
public:
  static ISoftwareKeyConnection* create();
  static ISoftwareKeyConnection* createInstance();

  virtual ~ISoftwareKeyConnection();

  virtual int connect(
    const ICertificate& aCertToConnect,
    ISoftwareKeyPingRP& aCallBack) = 0;

  virtual int disconnect() = 0;

  virtual int encryptData(
    const TBlob& aData,
    TBlob& aEncrypted) = 0;

  virtual int decryptData(
    const TBlob& aEncrypted,
    TBlob& aData) = 0;

  virtual bool isConnected(
    bool afCheckActivity) const = 0;
};

