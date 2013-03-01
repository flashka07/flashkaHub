#pragma once

class IByteStream
{
public:
  virtual int send(
    const void* apMessage,
    size_t aszLength) = 0;

  virtual int receive(
    void* apBuffer,
    size_t aszBufferSize,
    size_t& aszReceivedBytes) = 0;
};