#pragma once

// интерфейс для принятия действий
// при потере соединения с ключом

class ISoftwareKeyPingRP
{
public:

  virtual void onPingFail() = 0;
};