#pragma once

class ISocket;
class ICertificate;
//class CredHandle;
//class SecHandle;

class __declspec(dllexport) ISecurityChannel
{
public:
  static ISecurityChannel* create();
  static ISecurityChannel* createInstance();

  virtual ~ISecurityChannel();

  virtual int authenticate(
    ISocket& aSocket,
    const ICertificate& aCertificate,
    bool afServerMode = false) = 0;

  virtual int renegotiate() = 0;
  virtual int shutdown(
    bool afSendNotification) = 0;

  virtual CredHandle& getCreditionals() = 0;
  virtual SecHandle& getContext() = 0;

  virtual bool isInServerMode() const = 0;
  virtual bool isEstablished() const = 0;

  virtual ISocket* getAttachedSocket() = 0;

  virtual size_t getExtraDataSize() const = 0;
  virtual size_t getExtraData(void* apBuffer) const = 0;
};