#pragma once
#include "iSecurityChannelStream.h"

#include <vector>

typedef unsigned char BYTE;
class ISocketStream;

class TSecurityChannelStream : public ISecurityChannelStream
{
public:
  TSecurityChannelStream();
  ~TSecurityChannelStream();

  int attach(ISecurityChannel& aChannel);
  int detach();

  bool isAttached() const;

  int send(
    const void* apMessage,
    size_t aszLength);

  int receive(
    void* apBuffer,
    size_t aszBufferSize,
    size_t& aszReceivedBytes);

private:
  int getStreamSizes(
    ISecurityChannel& aChannel);

  int initBuffers();

  // class data
  ISecurityChannel* m_pSecurityChannel;
  ISocketStream* m_pSocketStream;

  std::vector<BYTE> m_vInBuffer;
  std::vector<BYTE> m_vOutBuffer;

  SecBufferDesc m_outBuffDesc;
  SecBuffer m_outSecBuff[4];

  SecBufferDesc m_inBuffDesc;
  SecBuffer m_inSecBuff[4];

  size_t m_szHeaderLength;
  size_t m_szMessageLength;
  size_t m_szTrailerLength;
};