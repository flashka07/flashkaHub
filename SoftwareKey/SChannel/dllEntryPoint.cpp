#include <Windows.h>

BOOL WINAPI DllMain(
  HINSTANCE hinstDLL,
  DWORD fdwReason,
  LPVOID lpvReserved)
{
  switch(fdwReason)
  {
  case DLL_PROCESS_ATTACH:
    {
      WSADATA wsaData;
      int nResult = ::WSAStartup(MAKEWORD(2,2), &wsaData);
      if(nResult) 
        return FALSE;
    }
    break;
  case DLL_PROCESS_DETACH:
    ::WSACleanup();
  }
  
  return TRUE;
}