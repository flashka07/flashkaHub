#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include <iostream>
#include <vector>

#pragma comment(lib, "secur32.lib")
// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

static const DWORD c_dwMaxMessage = 12000;

bool SendBytes(
  SOCKET aSocket, 
  BYTE* apBuf, 
  DWORD adwBuf);

bool ReceiveBytes(
  SOCKET aSocket, 
  PBYTE apBuf, 
  DWORD adwBuf, 
  DWORD* apdwRead);

void cleanup()
{
  WSACleanup();
  system("pause");
  exit(0);
}

bool SendMsg(
  SOCKET aSocket, 
  BYTE* apBuf, 
  DWORD adwBuf)
{
  if(!adwBuf)
    return true;

  if (!SendBytes(aSocket, (BYTE*)&adwBuf, sizeof(adwBuf)))
      return false;

  if(!SendBytes(aSocket, apBuf, adwBuf))
  {
    return false;
  }
  return true;
}

bool ReceiveMsg(
  SOCKET aSocket, 
  BYTE* apBuf, 
  DWORD adwBuf, 
  DWORD* apdwRead)
{
  DWORD dwRead = 0;
  DWORD dwData = 0;

  if(!ReceiveBytes(
    aSocket, 
    (BYTE*)&dwData, 
    sizeof(dwData), 
    &dwRead))
  {
    return false;
  }

  if(sizeof(dwData) != dwRead)
  {
    return false;
  }

  if (!ReceiveBytes (
    aSocket, 
    apBuf, 
    dwData, 
    &dwRead))
  {
     return false;
  }

  if(dwRead != dwData)
  {
    return false;
  }

  *apdwRead = dwRead;

  return true;
}  

bool SendBytes(
  SOCKET aSocket, 
  BYTE* apBuf, 
  DWORD adwBuf)
{
  PBYTE pTemp = apBuf;
  int nSent = 0;
  int nRemaining = adwBuf;

  if (!adwBuf)
  {
    return true;
  }

  while(nRemaining) 
  {
    nSent = send(aSocket, (const char *)pTemp, nRemaining, 0);
    if (SOCKET_ERROR == nSent) 
    {
      std::cout << std::hex << 
        "error in send = " << ::GetLastError() << '\n';
      return false;
    }

    pTemp += nSent;
    nRemaining -= nSent;
  }

  return true;
}

bool ReceiveBytes(
  SOCKET aSocket, 
  PBYTE apBuf, 
  DWORD adwBuf, 
  DWORD* apdwRead)
{
  PBYTE pTemp = apBuf;
  int nRemaining = adwBuf;

  while(nRemaining) 
  {
    int nRead = recv(
      aSocket, 
      (char *)pTemp, 
      nRemaining, 
      0);
    if (0 == nRead)
    {
      break;
    }

    if(SOCKET_ERROR == nRead) 
    {
      std::cout << std::hex << 
        "error in recv = " << ::GetLastError() << '\n';
      return false;
    }

    nRemaining -= nRead;
    pTemp += nRead;
  }

  *apdwRead = adwBuf - nRemaining;
  return true;
}

void printHexDump(DWORD length, PBYTE buffer)
{
  DWORD i,count,index;
  CHAR rgbDigits[]="0123456789abcdef";
  CHAR rgbLine[100];
  char cbLine;

  for(index = 0; length;
     length -= count, buffer += count, index += count) 
  {
     count = (length > 16) ? 16:length;

     sprintf_s(rgbLine, 100, "%4.4x  ",index);
     cbLine = 6;

     for(i=0;i<count;i++) 
     {
        rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
        rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
        if(i == 7) 
        {
           rgbLine[cbLine++] = ':';
        } 
        else 
        {
           rgbLine[cbLine++] = ' ';
        }
     }
     for(; i < 16; i++) 
     {
        rgbLine[cbLine++] = ' ';
        rgbLine[cbLine++] = ' ';
        rgbLine[cbLine++] = ' ';
     }

     rgbLine[cbLine++] = ' ';

     for(i = 0; i < count; i++) 
     {
        if(buffer[i] < 32 || buffer[i] > 126) 
        {
           rgbLine[cbLine++] = '.';
        } 
        else 
        {
           rgbLine[cbLine++] = buffer[i];
        }
     }

     rgbLine[cbLine++] = 0;
     printf("%s\n", rgbLine);
  }
}

// COPYPASTE FROM SERVER - BEGIN

CredHandle g_hCred;
SecHandle  g_hContext;

SecPkgContext_StreamSizes g_streamSizes = {0};
bool g_fStreamSizesInit = false;

const SecPkgContext_StreamSizes& getStreamSizes()
{
  if(!g_fStreamSizesInit)
  {
    SECURITY_STATUS ssResult = ::QueryContextAttributes(
    &g_hContext,
    SECPKG_ATTR_STREAM_SIZES,
    &g_streamSizes);
    if(ssResult != SEC_E_OK)
    {
      std::cout << std::hex <<
        "Error in ::QueryContextAttributes = " << ssResult << '\n';
    }
    else
    {
      g_fStreamSizesInit = true;
    }
  }

  return g_streamSizes;
}

bool encryptMessage(
  const BYTE* apMessage,
  DWORD adwMessageLength,
  BYTE* apEncrypted,
  DWORD& adwEncryptedLength)
{
  if(adwMessageLength > getStreamSizes().cbMaximumMessage)
  {
    std::cout << "Message is too big\n";
    return false;
  }

  size_t szTotalSize = getStreamSizes().cbHeader 
    + getStreamSizes().cbMaximumMessage
    + getStreamSizes().cbTrailer;

  std::vector<BYTE> vBuffer(szTotalSize, 0);

  SecBufferDesc buffDesc = {0};
  SecBuffer secBuff[3] = {0};

  buffDesc.cBuffers = 3;
  buffDesc.pBuffers = secBuff;

  secBuff[0].BufferType = SECBUFFER_STREAM_HEADER;
  secBuff[0].cbBuffer = getStreamSizes().cbHeader;
  secBuff[0].pvBuffer = &vBuffer[0];

  secBuff[1].BufferType = SECBUFFER_DATA;
  secBuff[1].cbBuffer = adwMessageLength;
  secBuff[1].pvBuffer = &vBuffer[0] + getStreamSizes().cbHeader;
  memcpy(secBuff[1].pvBuffer, apMessage, adwMessageLength);

  secBuff[2].BufferType = SECBUFFER_STREAM_TRAILER;
  secBuff[2].cbBuffer = getStreamSizes().cbTrailer;
  secBuff[2].pvBuffer = (BYTE*)secBuff[1].pvBuffer + adwMessageLength;

  SECURITY_STATUS ssResult = ::EncryptMessage(
    &g_hContext,
    0,
    &buffDesc,
    0);
  if(ssResult != SEC_E_OK)
  {
    std::cout << std::hex <<
      "Error in ::EncryptMessage = " << ssResult << '\n';
    return false;
  }

  memcpy(
    apEncrypted, 
    &vBuffer[0], 
    secBuff[0].cbBuffer + secBuff[1].cbBuffer + secBuff[2].cbBuffer);
  adwEncryptedLength = secBuff[1].cbBuffer;

  return true;
}

bool decryptMessage(
  const BYTE* apEncrypted,
  DWORD adwEncryptedLength,
  BYTE* apMessage,
  DWORD& adwMessageLength)
{
  if(adwMessageLength > getStreamSizes().cbMaximumMessage)
  {
    std::cout << "Message is too big\n";
    return false;
  }

  size_t szTotalSize = getStreamSizes().cbHeader 
    + getStreamSizes().cbMaximumMessage
    + getStreamSizes().cbTrailer;

  std::vector<BYTE> vBuffer(szTotalSize, 0);
  memcpy(&vBuffer[0], apEncrypted, adwEncryptedLength);

  SecBufferDesc bufferDesc = {0};
  SecBuffer secBuff[4] = {0};

  bufferDesc.cBuffers = 4;
  bufferDesc.pBuffers = secBuff;

  secBuff[0].BufferType = SECBUFFER_DATA;
  secBuff[0].cbBuffer = adwEncryptedLength;
  secBuff[0].pvBuffer = &vBuffer[0];

  secBuff[1].BufferType = SECBUFFER_EMPTY;
  secBuff[1].pvBuffer = NULL;
  secBuff[1].cbBuffer = 0;

  secBuff[2].BufferType = SECBUFFER_EMPTY;
  secBuff[2].pvBuffer = NULL;
  secBuff[2].cbBuffer = 0;

  secBuff[3].BufferType = SECBUFFER_EMPTY;
  secBuff[3].pvBuffer = NULL;
  secBuff[3].cbBuffer = 0;

  ULONG ulQ = 0;
  SECURITY_STATUS ssResult = SEC_E_INCOMPLETE_MESSAGE;
  for(;ssResult == SEC_E_INCOMPLETE_MESSAGE;)
  {
    ssResult = ::DecryptMessage(
      &g_hContext,
      &bufferDesc,
      0,
      &ulQ);
  }

  if(ssResult != SEC_E_OK)
  {
    std::cout << std::hex <<
      "Error in ::DecryptMessage = " << ssResult << '\n';

    return false;
  }

  memcpy(apMessage, secBuff[1].pvBuffer, secBuff[1].cbBuffer);
  adwMessageLength = secBuff[1].cbBuffer;

  return true;
}

bool sendEncrypted(
  SOCKET aSocket,
  const void* apOutMessage,
  size_t aszMsgLength)
{
  size_t szTotalSize = getStreamSizes().cbHeader 
    + getStreamSizes().cbMaximumMessage
    + getStreamSizes().cbTrailer;

  std::vector<BYTE> vBuffer(szTotalSize, 0);

  SecBufferDesc buffDesc = {0};
  SecBuffer secBuff[4] = {0};

  buffDesc.cBuffers = 4;
  buffDesc.pBuffers = secBuff;

  secBuff[0].BufferType = SECBUFFER_STREAM_HEADER;
  secBuff[0].cbBuffer = getStreamSizes().cbHeader;
  secBuff[0].pvBuffer = &vBuffer[0];

  secBuff[1].BufferType = SECBUFFER_DATA;

  secBuff[2].BufferType = SECBUFFER_STREAM_TRAILER;

  secBuff[3].BufferType = SECBUFFER_EMPTY;
  secBuff[3].pvBuffer = NULL;
  secBuff[3].cbBuffer = 0;

  while(aszMsgLength > 0)
  {
    size_t szEncryptSize = min(
      aszMsgLength, 
      getStreamSizes().cbMaximumMessage);
    
    secBuff[1].cbBuffer = szEncryptSize;
    secBuff[1].pvBuffer = &vBuffer[0] + secBuff[0].cbBuffer;
    memcpy(secBuff[1].pvBuffer, apOutMessage, szEncryptSize);

    secBuff[2].cbBuffer = getStreamSizes().cbTrailer;
    secBuff[2].pvBuffer = static_cast<BYTE*>(secBuff[1].pvBuffer) 
      + szEncryptSize;

    SECURITY_STATUS ssResult = ::EncryptMessage(
      &g_hContext,
      0,
      &buffDesc,
      0);
    if(ssResult != SEC_E_OK)
    {
      std::cout << std::hex <<
        "Error in ::EncryptMessage = " << ssResult << '\n';
      return false;
    }
    
    std::cout << "\nEncrypted:\n";
    printHexDump(
      secBuff[0].cbBuffer + secBuff[1].cbBuffer + secBuff[2].cbBuffer,
      static_cast<BYTE*>(secBuff[0].pvBuffer));

    bool fResult = SendMsg(
      aSocket, 
      static_cast<BYTE*>(secBuff[0].pvBuffer),
      secBuff[0].cbBuffer + secBuff[1].cbBuffer + secBuff[2].cbBuffer);
    if(!fResult)
    {
      std::cout << "cannot send message\n";
      return false;
    }

    apOutMessage = static_cast<const BYTE*>(apOutMessage) + szEncryptSize;
    aszMsgLength -= szEncryptSize;
  }

  return true;
}

bool receiveEncrypted(
  SOCKET aSocket,
  void* apMessage,
  size_t aszBufferSize,
  size_t& aszRecieved,
  long* aplDecryptReturn = NULL)
{
  size_t szTotalSize = getStreamSizes().cbHeader 
    + getStreamSizes().cbMaximumMessage
    + getStreamSizes().cbTrailer;

  std::vector<BYTE> vBuffer(szTotalSize, 0);

  SecBufferDesc bufferDesc = {0};
  SecBuffer secBuff[4] = {0};

  bufferDesc.cBuffers = 4;
  bufferDesc.pBuffers = secBuff;

  size_t szRawRead = 0;
  SECURITY_STATUS ssResult = SEC_E_INCOMPLETE_MESSAGE;
  while(ssResult == SEC_E_INCOMPLETE_MESSAGE)
  {
    DWORD dwRead = 0;
    bool fResult = ReceiveMsg(
      aSocket, 
      &vBuffer[0], 
      szTotalSize - szRawRead,
      &dwRead);
    if(!fResult)
    {
      std::cout << "cannot receive message\n";
      return false;
    }
    szRawRead += dwRead;

    secBuff[0].BufferType = SECBUFFER_DATA;
    secBuff[0].cbBuffer = szRawRead;
    secBuff[0].pvBuffer = &vBuffer[0];
    
    secBuff[1].BufferType = SECBUFFER_EMPTY;
    secBuff[1].cbBuffer = 0;
    secBuff[1].pvBuffer = NULL;
    secBuff[2].BufferType = SECBUFFER_EMPTY;
    secBuff[2].cbBuffer = 0;
    secBuff[2].pvBuffer = NULL;
    secBuff[3].BufferType = SECBUFFER_EMPTY;
    secBuff[3].cbBuffer = 0;
    secBuff[3].pvBuffer = NULL;

    ULONG ulQop = 0;
    ssResult = ::DecryptMessage(
      &g_hContext,
      &bufferDesc,
      0,
      &ulQop);
  }

  if(ssResult != SEC_E_OK)
  {
    // TODO: remake this
    // SEC_I_CONTEXT_EXPIRED - shutdown
    // SEC_I_RENEGOTIATE - need to renegotate
    if(aplDecryptReturn &&
       (ssResult == SEC_I_CONTEXT_EXPIRED ||
        ssResult == SEC_I_RENEGOTIATE))
    {
      *aplDecryptReturn = ssResult;
      return true;
    }
    else
    {
      if(aplDecryptReturn)
        *aplDecryptReturn = ssResult;

      std::cout << std::hex <<
        "Error in ::DecryptMessage = " << ssResult << '\n';
      return false;
    }
  }

  aszRecieved = min(aszBufferSize, secBuff[1].cbBuffer);
  memcpy(apMessage, secBuff[1].pvBuffer, aszRecieved);

  return true;
}

void shutdownChannel(
  SOCKET aSocket,
  bool afSendNotification)
{
  DWORD dwShutdownToken = SCHANNEL_SHUTDOWN;
  SecBufferDesc shutDownBufferDesc;
  SecBuffer shutDownBuffers[1];
  shutDownBufferDesc.cBuffers = 1;
  shutDownBufferDesc.pBuffers = shutDownBuffers;
  shutDownBufferDesc.ulVersion = SECBUFFER_VERSION;
  shutDownBuffers[0].pvBuffer = &dwShutdownToken;
  shutDownBuffers[0].BufferType = SECBUFFER_TOKEN;
  shutDownBuffers[0].cbBuffer = sizeof(dwShutdownToken);

  ::ApplyControlToken(&g_hContext, &shutDownBufferDesc);

  std::vector<BYTE> vBuff(c_dwMaxMessage, 0);
  shutDownBuffers[0].BufferType = SECBUFFER_TOKEN;
  shutDownBuffers[0].pvBuffer = &vBuff[0];
  shutDownBuffers[0].cbBuffer = c_dwMaxMessage;

  ULONG ulContextAttr = 0;
  TimeStamp tsLifetime;
  SECURITY_STATUS ssResult = ::InitializeSecurityContext(
    &g_hCred, 
    &g_hContext, 
    NULL,
    0,//ISC_REQ_ALLOCATE_MEMORY, // mb another flags
    0, 
    0, 
    NULL, 
    0, 
    NULL,
    &shutDownBufferDesc, 
    &ulContextAttr, 
    &tsLifetime);
  if(ssResult < 0)
  {
    std::cout << std::hex 
      << "error in ::InitializeSecurityContext = " << ssResult << '\n';
    return;
  }

  if(afSendNotification)
  {
    bool fResult = SendMsg(
      aSocket,
      static_cast<BYTE*>(shutDownBuffers[0].pvBuffer),
      shutDownBuffers[0].cbBuffer);
    if(!fResult)
    {
      std::cout << "cannot send shutdown message\n";
    }
  }
}

// COPYPASTE FROM SERVER - END

bool genClientContext(
  BYTE* apbIn,
  DWORD adwIn,
  BYTE* apbOut,
  DWORD* apdwOut,
  bool* apfDone,
  char* astrTarget,
  CredHandle* aphCred,
  SecHandle* aphContext)
{
  TimeStamp tsLifetime;
  SECURITY_STATUS ssResult = 0;
  if(!apbIn)
  {
    SCHANNEL_CRED schCred = {0};
    schCred.dwVersion = SCHANNEL_CRED_VERSION;
    schCred.cCreds = 0;
    schCred.paCred = NULL;
    schCred.hRootStore = 0;
    schCred.grbitEnabledProtocols = SP_PROT_TLS1_2;
    /*schCred.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK
      | SCH_CRED_MANUAL_CRED_VALIDATION;*/
    
    ssResult = ::AcquireCredentialsHandle(
      NULL,
      "Schannel",
      SECPKG_CRED_OUTBOUND,
      NULL,
      &schCred,
      NULL,
      NULL,
      aphCred,
      &tsLifetime);
    if(ssResult != SEC_E_OK)
    {
      // SEC_E_INSUFFICIENT_MEMORY, SEC_E_INTERNAL_ERROR, 
      // SEC_E_NO_CREDENTIALS, SEC_E_NOT_OWNER,
      // SEC_E_SECPKG_NOT_FOUND, SEC_E_UNKNOWN_CREDENTIALS
      std::cout << std::hex <<
        "Error in ::AcquireCredentialsHandle = " << ssResult << '\n';
      return false;
    }
  }

  SecBufferDesc outBuffDesc = {0};
  SecBuffer outSecBuff = {0};
  SecBufferDesc inBuffDesc = {0};
  SecBuffer inSecBuff[2] = {0};

  // prepare output
  outBuffDesc.ulVersion = 0;
  outBuffDesc.cBuffers = 1;
  outBuffDesc.pBuffers = &outSecBuff;

  outSecBuff.cbBuffer = *apdwOut;
  outSecBuff.BufferType = SECBUFFER_TOKEN;
  outSecBuff.pvBuffer = apbOut;

  ULONG ulContextAttr = 0;
  if(apbIn)
  {
    // prepare input
    inBuffDesc.ulVersion = 0;
    inBuffDesc.cBuffers = 2;
    inBuffDesc.pBuffers = inSecBuff;

    inSecBuff[0].BufferType = SECBUFFER_TOKEN;
    inSecBuff[0].cbBuffer = adwIn;
    inSecBuff[0].pvBuffer = apbIn;

    inSecBuff[1].BufferType = SECBUFFER_EMPTY;
    inSecBuff[1].cbBuffer = 0;
    inSecBuff[1].pvBuffer = NULL;

    ssResult = ::InitializeSecurityContext(
      aphCred,
      aphContext,
      astrTarget,
      ISC_REQ_MANUAL_CRED_VALIDATION,
      0,
      0, // not used in Schannel
      &inBuffDesc,
      0,
      NULL,
      &outBuffDesc,
      &ulContextAttr,
      &tsLifetime);
  }
  else
  {
    ssResult = ::InitializeSecurityContext(
      aphCred,
      NULL,
      astrTarget,
      ISC_REQ_MANUAL_CRED_VALIDATION,
      0,
      0,
      NULL,
      0,
      aphContext,
      &outBuffDesc,
      &ulContextAttr,
      &tsLifetime);
  }

  if(ssResult < 0)
  {
    std::cout << std::hex 
      << "error in ::InitializeSecurityContext = " << ssResult << '\n';
    return false;
  }

  if(ssResult == SEC_I_COMPLETE_NEEDED ||
     ssResult == SEC_I_COMPLETE_AND_CONTINUE)
  {
    ssResult = ::CompleteAuthToken(aphContext, &outBuffDesc);
    if(ssResult < 0)
    {
      std::cout << std::hex <<
        "Error in ::CompleteAuthToken = " << ssResult << '\n';
      return false;
    }
  }

  *apfDone = !(
    ssResult == SEC_I_CONTINUE_NEEDED ||
    ssResult == SEC_I_COMPLETE_NEEDED ||
    ssResult == SEC_I_COMPLETE_AND_CONTINUE);
  *apdwOut = outSecBuff.cbBuffer;

  std::cout << "Token buffer generated " << outSecBuff.cbBuffer
    << " bytes:\n";
  printHexDump(outSecBuff.cbBuffer, (BYTE*)outSecBuff.pvBuffer);

  std::cout << std::hex
    << "::InitializeSecurityContext result = " 
    << ssResult << '\n';
  return true;
}

bool doAuthentication(
  SOCKET aSocket,
  CredHandle* aphCred,
  SecHandle* aphContext)
{
  std::vector<BYTE> vInBuffer(c_dwMaxMessage, 0);
  std::vector<BYTE> vOutBuffer(c_dwMaxMessage, 0);
  DWORD dwIn = 0;
  DWORD dwOut = c_dwMaxMessage;

  bool fDone = false;
  bool fResult = genClientContext(
    NULL,
    0,
    &vOutBuffer[0],
    &dwOut,
    &fDone,
    "192.168.2.40",
    aphCred,
    aphContext);
  if(!fResult)
  {
    std::cout << "error in first genClientContext\n";
    return false;
  }

  if(!SendMsg(aSocket, &vOutBuffer[0], dwOut))
  {
    std::cout << "cannot send message = " << 
      ::GetLastError() << '\n';
    return false;
  }

  while(!fDone)
  {
    if(!ReceiveMsg(aSocket, &vInBuffer[0], c_dwMaxMessage, &dwIn))
    {
      std::cout << "cannot receive message = " << 
        ::GetLastError() << '\n';
      return false;
    }

    dwOut = c_dwMaxMessage;
    fResult = genClientContext(
      &vInBuffer[0],
      dwIn,
      &vOutBuffer[0],
      &dwOut,
      &fDone,
      "192.168.2.40",
      aphCred,
      aphContext);
    if(!fResult)
    {
      std::cout << "error in genClientContext\n";
      return false;
    }

    if(!SendMsg(aSocket, &vOutBuffer[0], dwOut))
    {
      std::cout << "cannot send message in cycle = " << 
        ::GetLastError() << '\n';
      return false;
    }
  }

  return true;
}

bool connectAuthSocket(
  SOCKET* apSocket,
  CredHandle* aphCred,
  SecHandle* aphContext)
{
  addrinfo* pResultAddrInfo = NULL;
  addrinfo hintsAddrInfo = {0};
  hintsAddrInfo.ai_family = AF_INET;
  hintsAddrInfo.ai_socktype = SOCK_STREAM;
  hintsAddrInfo.ai_protocol = IPPROTO_TCP;

  // Resolve the server address and port
  int nResult = getaddrinfo(
    "localhost",
    DEFAULT_PORT, 
    &hintsAddrInfo, 
    &pResultAddrInfo);
  if(nResult) 
  {
    std::cout << std::hex
        << "Cannot getaddrinfo = " << nResult << '\n';
    return false;
  }
  // Attempt to connect to an address until one succeeds
  for(addrinfo* ptr = pResultAddrInfo; ptr != NULL; ptr=ptr->ai_next) 
  {
    // Create a SOCKET for connecting to server
    *apSocket = socket(
      ptr->ai_family, 
      ptr->ai_socktype, 
      ptr->ai_protocol);
    if(*apSocket == INVALID_SOCKET) 
    {
      std::cout << std::hex
        << "Cannot create socket = " << ::GetLastError() << '\n';
      return false;
    }

    // Connect to server.
    int nResult = connect(*apSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
    if(nResult == SOCKET_ERROR) 
    {
      closesocket(*apSocket);
      *apSocket = INVALID_SOCKET;
      continue;
    }
    break;
  }

  if(*apSocket == INVALID_SOCKET)
  {
    std::cout << std::hex
        << "Socked is not connected\n";
    return false;
  }

  freeaddrinfo(pResultAddrInfo);

  if(!doAuthentication(*apSocket, aphCred, aphContext))
  {
    std::cout << "error in doAuthentication\n";
    return false;
  }

  return true;
}

DWORD init()
{
  WSADATA wsaData;

  // Initialize Winsock
  int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
  if (iResult != 0) 
  {
      printf("WSAStartup failed with error: %d\n", iResult);
      return 1;
  }
  return 0;
}

int main()
{
  DWORD dwResult = init();
  if(dwResult)
  {
    std::cout << std::hex <<
      "Error in init = " << dwResult << '\n';
    cleanup();
    return 0;
  }

  CredHandle hCred = {0};
  SecHandle hContext = {0};
  SOCKET sockClient = 0;
  bool fResult = connectAuthSocket(
    &sockClient,
    &hCred,
    &hContext);
  if(!fResult)
  {
    std::cout << "cannot connect auth socket\n";
    closesocket(sockClient);
    cleanup();
    return -1;
  }

  g_hCred = hCred;
  g_hContext = hContext;

  // workflow
  char cBuf[500] = "";
  size_t szReceived = 0;
  fResult = receiveEncrypted(
    sockClient,
    cBuf,
    500,
    szReceived);
  if(!fResult)
  {
    std::cout << "Error in receiveEncrypted\n";
  }
  else
  {
    std::cout << cBuf << '\n';
  }

  char cHello[] = "Hello to Server!!!";
  fResult = sendEncrypted(
    sockClient,
    cHello,
    sizeof(cHello));
  if(!fResult)
  {
    std::cout << "Error in sendEncrypted\n";
  }

  // shutting down
  shutdownChannel(sockClient, true);

  shutdown(sockClient, 2);
  closesocket(sockClient);
  ::FreeCredentialsHandle(&hCred);
  ::DeleteSecurityContext(&hContext);
  cleanup();
  return 0;
}