#pragma once
#include <string>

class Socket
{
public:
  Socket();
  ~Socket();

  int listen(const std::string& astrPort);
  int connect(
    const std::string& astrAddress,
    const std::string& astrPort);
private:
  int initialize();
  
  unsigned int* m_pSocket;
};