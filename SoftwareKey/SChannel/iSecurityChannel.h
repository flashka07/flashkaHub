#pragma once

class ISocket;
class ICertificate;
//class CredHandle;
//class SecHandle;

class ISecurityChannel
{
public:
  virtual int authenticate(
    ISocket& aSocket,
    const ICertificate& aCertificate) = 0;
  virtual int renegotiate() = 0;
  virtual int shutdown(
    bool afSendNotification) = 0;

  virtual CredHandle& getCreditionals() = 0;
  virtual SecHandle& getContext() = 0;

  virtual bool isEstablished() const = 0;

  virtual ISocket* getAttachedSocket() = 0;

  virtual size_t getExtraDataSize() const = 0;
  virtual size_t getExtraData(void* apBuffer) const = 0;
};