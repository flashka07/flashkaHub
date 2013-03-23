#pragma once
#include "iSocketStream.h"

class TSocketStream : public ISocketStream
{
public:
  TSocketStream();
  ~TSocketStream();

  int attach(ISocket& aSocket);
  int detach();

  int send(
    const void* apMessage,
    size_t aszLength);

  int receive(
    void* apBuffer,
    size_t aszBufferSize,
    size_t& aszReceivedBytes,
    unsigned int aunTimeout);

  bool isAttached() const;

private:
  int sendBytes(
    const void* apBuf, 
    size_t aszBuf);

  int receiveBytes(
    void* apBuf, 
    size_t aszBuf, 
    size_t& aszRead,
    unsigned int aunTimeout);

  // class data
  ISocket* m_pSocket;
};