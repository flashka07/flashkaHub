#pragma once

class IByteStream
{
public:
  // send data
  virtual int send(
    const void* apMessage,
    size_t aszLength) = 0;

  // send data with timeout in miliseconds
  // (if aunTimeout = 0 then call is blocked)
  virtual int receive(
    void* apBuffer,
    size_t aszBufferSize,
    size_t& aszReceivedBytes,
    unsigned int aunTimeout = 0) = 0;
};