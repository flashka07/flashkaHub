#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>

#include <winsock2.h>
#include <ws2tcpip.h>


#include <iostream>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

static DWORD g_cbMaxMessage = 0;
static BYTE* g_pInBuf = NULL;
static BYTE* g_pOutBuf = NULL;
static const CERT_CONTEXT* g_pCertContext = NULL;

CredHandle g_hCred;
SecHandle  g_hContext;

SecPkgContext_StreamSizes g_streamSizes = {0};
bool g_fStreamSizesInit = false;

bool SendMsg(
  SOCKET aSocket, 
  BYTE* apBuf, 
  DWORD adwBuf);

bool ReceiveMsg(
  SOCKET aSocket, 
  BYTE* apBuf, 
  DWORD adwBuf, 
  DWORD* apdwRead);

bool SendBytes(
  SOCKET aSocket, 
  BYTE* apBuf, 
  DWORD adwBuf);

bool ReceiveBytes(
  SOCKET aSocket, 
  PBYTE apBuf, 
  DWORD adwBuf, 
  DWORD* apdwRead);

void printHexDump(DWORD length, PBYTE buffer);

void cleanup()
{
   if(g_pInBuf)
      free(g_pInBuf);

   if(g_pOutBuf)
      free(g_pOutBuf);

   if(g_pCertContext)
     ::CertFreeCertificateContext(g_pCertContext);

   WSACleanup();
   system("pause");
   exit(0);
}

//CredHandle getCredHandle()
//{
//  /*ULONG ulPackCount = 0;
//  SecPkgInfo* pSecPkgInfo = NULL;*/
//
//  //SECURITY_STATUS ssResult = ::EnumerateSecurityPackages(
//  //  &ulPackCount,
//  //  &pSecPkgInfo);
//  //if(ssResult != SEC_E_OK)
//  //{
//  //  // SEC_E_INSUFFICIENT_MEMORY, SEC_E_INVALID_HANDLE, 
//  //  // SEC_E_SECPKG_NOT_FOUND
//  //  std::cout << std::hex <<
//  //    "Error in ::EnumerateSecurityPackages = " << ssResult << '\n';
//  //  return CredHandle();
//  //}
//  //std::cout << "Available Security Packages:\n";
//  //for(ULONG i=0; i<ulPackCount; ++i)
//  //{
//  //  std::cout << pSecPkgInfo->Name << '\n';
//  //  ++pSecPkgInfo;
//  //}
//  // not needed
//  //::FreeContextBuffer(pSecPkgInfo);
//
//  SCHANNEL_CRED scCred = {0};
//  scCred.dwVersion = SCHANNEL_CRED_VERSION;
//  scCred.cCreds = 0; // number of certificates
//  scCred.paCred = NULL; // array of certificates
//  scCred.hRootStore = NULL; // must be specified for server
//  scCred.cSupportedAlgs = 0; // using default
//  scCred.palgSupportedAlgs = NULL; // using default
//  scCred.grbitEnabledProtocols = 
//    SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_2_SERVER;
//  scCred.dwMinimumCipherStrength = 0; // using default
//  scCred.dwMaximumCipherStrength = 0; // using default
//  scCred.dwSessionLifespan = 0; // using default
//  scCred.dwFlags = 0; // TODO: set flags
//  scCred.dwCredFormat = 0;
//
//  
//  CredHandle hCred = {0};
//  SECURITY_STATUS ssResult = ::AcquireCredentialsHandle(
//    NULL, // use Schannel
//    "Schannel", // can be used result from EnumerateSecurityPackages
//    SECPKG_CRED_INBOUND, // or SECPKG_CRED_OUTBOUND
//    NULL, // pvLogonID: use Schannel
//    &scCred,
//    NULL, // pGetKeyFn: not used
//    NULL, // pvGetKeyArgument: not used 
//    &hCred,
//    NULL); // ptsExpiry: optionally
//  if(ssResult != SEC_E_OK)
//  {
//    // SEC_E_INSUFFICIENT_MEMORY, SEC_E_INTERNAL_ERROR, 
//    // SEC_E_NO_CREDENTIALS, SEC_E_NOT_OWNER,
//    // SEC_E_SECPKG_NOT_FOUND, SEC_E_UNKNOWN_CREDENTIALS
//    std::cout << std::hex <<
//      "Error in ::EnumerateSecurityPackages = " << ssResult << '\n';
//    return hCred;
//  }
//}

//void work(SOCKET sock)
//{
//  std::cout << "Schannel test - Server\n\n";
//  
//  CredHandle hCred = getCredHandle();
//
//  SecBufferDesc secBuffDescFromClient = {0};
//  CtxtHandle newContext = {0};
//  SecBufferDesc secBuffDescToClient = {0};
//  ULONG ulOutContextAttr = 0;
//  SECURITY_STATUS ssResult = ::AcceptSecurityContext(
//    &hCred,
//    NULL,
//    &secBuffDescFromClient,
//    ASC_REQ_MUTUAL_AUTH | ASC_REQ_STREAM,
//    0, // not used
//    &newContext,
//    &secBuffDescToClient,
//    &ulOutContextAttr,
//    NULL); // optional
//  if(ssResult != SEC_E_OK)
//  {
//    // SEC_E_INCOMPLETE_MESSAGE, SEC_E_INSUFFICIENT_MEMORY, 
//    // SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE,
//    // SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED,
//    // SEC_E_NO_AUTHENTICATING_AUTHORITY,
//    // SEC_E_NO_CREDENTIALS, SEC_E_UNSUPPORTED_FUNCTION,
//    // SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED,
//    // SEC_I_CONTINUE_NEEDED, STATUS_LOGON_FAILURE
//    std::cout << std::hex <<
//      "Error in ::AcceptSecurityContext = " << ssResult << '\n';
//    /*::FreeCredentialsHandle(&hCred);
//    ::DeleteSecurityContext(&newContext);*/
//    return;
//  }
//
//  // Receive until the peer shuts down the connection
//  //do {
//
//  //    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
//  //    if (iResult > 0) {
//  //        printf("Bytes received: %d\n", iResult);
//
//  //    // Echo the buffer back to the sender
//  //        iSendResult = send( ClientSocket, recvbuf, iResult, 0 );
//  //        if (iSendResult == SOCKET_ERROR) {
//  //            printf("send failed with error: %x\n", WSAGetLastError());
//  //            
//  //            closesocket(ClientSocket);
//  //            WSACleanup();
//  //            return 1;
//  //        }
//  //        printf("Bytes sent: %d\n", iSendResult);
//  //    }
//  //    else if (iResult == 0)
//  //        printf("Connection closing...\n");
//  //    else  {
//  //        printf("recv failed with error: %x\n", WSAGetLastError());
//  //        closesocket(ClientSocket);
//  //        WSACleanup();
//  //        return 1;
//  //    }
//
//  //} while (iResult > 0);
//
//  ::FreeCredentialsHandle(&hCred);
//  ::DeleteSecurityContext(&newContext);
//}

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

  std::vector<BYTE> vBuff(g_cbMaxMessage, 0);
  shutDownBuffers[0].BufferType = SECBUFFER_TOKEN;
  shutDownBuffers[0].pvBuffer = &vBuff[0];
  shutDownBuffers[0].cbBuffer = g_cbMaxMessage;

  ULONG ulContextAttr = 0;
  TimeStamp tsLifetime;
  SECURITY_STATUS ssResult = ::AcceptSecurityContext(
    &g_hCred, 
    &g_hContext, 
    NULL,
    0, //ISC_REQ_ALLOCATE_MEMORY, // mb another flags
    0, 
    NULL, 
    &shutDownBufferDesc, 
    &ulContextAttr, 
    &tsLifetime);
  if(ssResult < 0)
  {
    std::cout << std::hex 
      << "error in ::AcceptSecurityContext = " << ssResult << '\n';
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

bool genServerContext(
  BYTE* apIn,
  DWORD adwIn,
  BYTE* apOut,
  DWORD* apdwOut,
  bool* apfDone,
  bool afNewConversation)
{
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
  outSecBuff.pvBuffer = apOut;

  // prepare input
  inBuffDesc.ulVersion = 0;
  inBuffDesc.cBuffers = 2;
  inBuffDesc.pBuffers = inSecBuff;

  inSecBuff[0].BufferType = SECBUFFER_TOKEN;
  inSecBuff[0].cbBuffer = adwIn;
  inSecBuff[0].pvBuffer = apIn;

  inSecBuff[1].BufferType = SECBUFFER_EMPTY;
  inSecBuff[1].cbBuffer = 0;
  inSecBuff[1].pvBuffer = NULL;

  std::cout << "Token buffer recieved " << inSecBuff[0].cbBuffer
    << " bytes:\n";
  printHexDump(inSecBuff[0].cbBuffer, (BYTE*)inSecBuff[0].pvBuffer);

  ULONG ulAttribs = ASC_REQ_MUTUAL_AUTH;
  TimeStamp stLifetime;
  SECURITY_STATUS ssResult = ::AcceptSecurityContext(
    &g_hCred,
    afNewConversation ? NULL : &g_hContext,
    &inBuffDesc,
    ulAttribs,
    0, // not used for Schannel
    &g_hContext,
    &outBuffDesc,
    &ulAttribs,
    &stLifetime);
  if(ssResult < 0)
  {
    std::cout << std::hex <<
      "Error in ::AcceptSecurityContext = " << ssResult << '\n';
  }

  if(ssResult == SEC_I_COMPLETE_NEEDED ||
     ssResult == SEC_I_COMPLETE_AND_CONTINUE)
  {
    ssResult = ::CompleteAuthToken(&g_hContext, &outBuffDesc);
    if(ssResult < 0)
    {
      std::cout << std::hex <<
        "Error in ::CompleteAuthToken = " << ssResult << '\n';
      return false;
    }
  }

  *apdwOut = outSecBuff.cbBuffer;
  std::cout << "Token buffer generated " << outSecBuff.cbBuffer
    << " bytes:\n";
  printHexDump(outSecBuff.cbBuffer, (BYTE*)outSecBuff.pvBuffer);

  *apfDone = !(
    ssResult == SEC_I_CONTINUE_NEEDED ||
    ssResult == SEC_I_COMPLETE_NEEDED ||
    ssResult == SEC_I_COMPLETE_AND_CONTINUE);

  std::cout << "::AcceptSecurityContext result = " 
    << ssResult << '\n';

  return true;
}

CERT_CONTEXT* getCertObject()
{
  CERT_CONTEXT* pCertContext = NULL;
  DWORD dwCertEncodingType = 0;
  DWORD dwCertContentType = 0;
  DWORD dwCertFormatType = 0;
  BOOL fResult = ::CryptQueryObject(
    CERT_QUERY_OBJECT_FILE,
    L"d:\\server_test.certkey.pem",
    CERT_QUERY_CONTENT_FLAG_ALL,
    CERT_QUERY_FORMAT_FLAG_ALL,
    0,
    &dwCertEncodingType,
    &dwCertContentType,
    &dwCertFormatType,
    NULL,
    NULL,
    (const void**)&pCertContext);
  if(!fResult)
  {
    std::cout << std::hex <<
        "Error in first ::CryptQueryObject = " << ::GetLastError() << '\n';
    return NULL;
  }

  return pCertContext;
}

bool doAuthentication(SOCKET aSocket)
{
  TimeStamp tsLifetime;

  /*{
    FILE* pCertFile = fopen("c:\\server_test.pem", "rb"); // ""
    if(!pCertFile)
    {
      std::cout << std::hex <<
        "Error: certificate server_test.pem not found\n";
      return false;
    }
    fseek(pCertFile, 0, SEEK_END);
    DWORD dwCertSize = ftell(pCertFile);
    BYTE* pbEncodedCert = new BYTE[dwCertSize];

    fseek(pCertFile, 0, SEEK_SET);
    if(dwCertSize != fread(
        pbEncodedCert, 
        sizeof(BYTE), 
        dwCertSize, 
        pCertFile))
    {
      delete[] pbEncodedCert;
      fclose(pCertFile);
      return false;
    }
    fclose(pCertFile);
    *(pbEncodedCert + dwCertSize - 1) = '\0';

    std::cout << "Certificate used (" << dwCertSize 
      << " bytes):\n" << pbEncodedCert << '\n';

    // get buffer size
    DWORD dwBinaryCertSize = 0;
    BOOL fResult = ::CryptStringToBinary(
      (char*)pbEncodedCert,
      dwCertSize,
      CRYPT_STRING_BASE64X509CRLHEADER,
      NULL,
      &dwBinaryCertSize,
      NULL,
      NULL);
    if(!fResult)
    {
      std::cout << std::hex <<
        "Error in first ::CryptStringToBinary = " << ::GetLastError() << '\n';
      delete[] pbEncodedCert;
      return false;
    }

    BYTE* pbBinEncodedCert = new BYTE[dwBinaryCertSize];
    DWORD dwFlags = 0;
    fResult = ::CryptStringToBinary(
      (char*)pbEncodedCert,
      dwCertSize,
      CRYPT_STRING_BASE64X509CRLHEADER,
      pbBinEncodedCert,
      &dwBinaryCertSize,
      NULL,
      &dwFlags);
    if(!fResult)
    {
      std::cout << std::hex <<
        "Error in second ::CryptStringToBinary = " << ::GetLastError() << '\n';
      delete[] pbEncodedCert;
      delete[] pbBinEncodedCert;
      return false;
    }
    delete[] pbEncodedCert;

    std::cout << "Flags in decode Certificate used: " 
      << std::hex << dwFlags << '\n';

    g_pCertContext = ::CertCreateCertificateContext(
      X509_ASN_ENCODING,
      pbEncodedCert,
      dwCertSize);
    if(!g_pCertContext)
    {
      std::cout << std::hex <<
        "Error in ::CertCreateCertificateContext = " << ::GetLastError() << '\n';
      delete[] pbBinEncodedCert;
      return false;
    }
    delete[] pbBinEncodedCert;
  }*/
  /*
  g_pCertContext = getCertObject();
  if(!g_pCertContext)
  {
    std::cout << std::hex <<
        "Error in getCertObject\n";
      return false;
  }*/

  HCERTSTORE hCertStore = ::CertOpenSystemStore(NULL, "MY");
  if(!hCertStore)
  {
    std::cout << std::hex <<
        "Error in ::CertOpenSystemStore = " << ::GetLastError() << '\n';
    return false;
  }

  std::cout << "allowed certificates:\n";
  PCCERT_CONTEXT pCertContext = NULL;
  while(pCertContext = ::CertEnumCertificatesInStore(
          hCertStore, 
          pCertContext))
  {
    std::cout << pCertContext->pCertInfo->Subject.pbData << '\n';
  }

  g_pCertContext = ::CertFindCertificateInStore(
    hCertStore,
    X509_ASN_ENCODING,
    0,
    CERT_FIND_SUBJECT_STR,
    L"i.drozdov",
    NULL);
  if(!g_pCertContext)
  {
    std::cout << std::hex <<
        "Error in ::CertFindCertificateInStore = " << ::GetLastError() << '\n';
    return false;
  }

  SCHANNEL_CRED schCred = {0};
  schCred.dwVersion = SCHANNEL_CRED_VERSION;
  schCred.cCreds = 1;
  schCred.paCred = &g_pCertContext;
  schCred.hRootStore = g_pCertContext->hCertStore;
  schCred.grbitEnabledProtocols = SP_PROT_TLS1_2;
  schCred.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
  
  SECURITY_STATUS ssResult = ::AcquireCredentialsHandle(
    NULL,
    UNISP_NAME,//"Schannel",
    SECPKG_CRED_INBOUND,
    NULL,
    &schCred,
    NULL,
    NULL,
    &g_hCred,
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

  if(hCertStore)
    ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
  
  bool fDone = false;
  bool fNewConversation = true;
  while(!fDone)
  {
    DWORD dwIn = 0;
    if(!ReceiveMsg(aSocket, g_pInBuf, g_cbMaxMessage, &dwIn))
    {
      std::cout << "cannot recieve message\n";
      return false;
    }

    DWORD dwOut = g_cbMaxMessage;
    bool fResult = genServerContext(
      g_pInBuf,
      dwIn,
      g_pOutBuf,
      &dwOut,
      &fDone,
      fNewConversation);
    if(!fResult)
    {
      std::cout << "error in getServerContext\n";
      return false;
    }

    fNewConversation = false;
    if(!SendMsg(aSocket, g_pOutBuf, dwOut))
    {
      std::cout << "cannot send message\n";
      return false;
    }
  }

  return true;
}

bool authSocket(SOCKET& aServerSocket)
{
  SOCKET sockListen = NULL;
  SOCKET sockClient = NULL;

  addrinfo* pResultAddrInfo = NULL;
  addrinfo hintsAddrInfo = {0};
  hintsAddrInfo.ai_family = AF_INET;
  hintsAddrInfo.ai_socktype = SOCK_STREAM;
  hintsAddrInfo.ai_protocol = IPPROTO_TCP;

  // Resolve the server address and port
  int nResult = getaddrinfo(
    NULL,
    DEFAULT_PORT, 
    &hintsAddrInfo, 
    &pResultAddrInfo);
  if(nResult) 
  {
    std::cout << std::hex
        << "Cannot getaddrinfo = " << nResult << '\n';
    return false;
  }

  sockListen = socket(
    pResultAddrInfo->ai_family, 
    pResultAddrInfo->ai_socktype, 
    pResultAddrInfo->ai_protocol);
  if(sockListen == INVALID_SOCKET)
  {
    std::cout << std::hex
      << "cannot create sockListen = " << ::GetLastError()
      << '\n';
    return false;
  }

  nResult = bind(
    sockListen, 
    pResultAddrInfo->ai_addr, 
    (int)pResultAddrInfo->ai_addrlen);
  if(nResult == SOCKET_ERROR)
  {
     std::cout << std::hex
      << "cannot bind to socket = " << ::GetLastError()
      << '\n';
    return false;
  }

  freeaddrinfo(pResultAddrInfo);

  nResult = listen(sockListen, 1);
  if(nResult == SOCKET_ERROR)
  {
    std::cout << std::hex
      << "cannot listen socket = " << ::GetLastError()
      << '\n';
    return false;
  }

  std::cout << "> Listening...\n";

  SOCKADDR sockAddrIncoming = {0};
  int nSize = sizeof(sockAddrIncoming);
  sockClient = accept(
    sockListen, 
    &sockAddrIncoming,
    &nSize);
  if(sockClient == INVALID_SOCKET)
  {
    std::cout << std::hex
      << "cannot accept client socket = " << ::GetLastError()
      << '\n';
    return false;
  }

  std::cout << "Client connected\n";

  closesocket(sockListen);

  aServerSocket = sockClient;

  return doAuthentication(sockClient);
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

  SecPkgInfo* pSecPkgInfo = NULL;

  SECURITY_STATUS ssResult = ::QuerySecurityPackageInfo(
    "Schannel",
    &pSecPkgInfo);
  if(ssResult != SEC_E_OK)
  {
    std::cout << std::hex <<
      "Error in ::QuerySecurityPackageInfo = " << ssResult << '\n';
    return ssResult;
  }

  g_cbMaxMessage = pSecPkgInfo->cbMaxToken;
  
  // not needed
  ::FreeContextBuffer(pSecPkgInfo);

  g_pInBuf = (BYTE*)malloc(g_cbMaxMessage);
  g_pOutBuf = (BYTE*)malloc(g_cbMaxMessage);

  if (NULL == g_pInBuf || NULL == g_pOutBuf)
  {
    std::cout << "Cannot allocate memory\n";
    return -1;
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

  while(true)
  {
    std::cout << "> waiting for client connection...\n";

    SOCKET sockServer = 0;
    if(!authSocket(sockServer))
    {
      std::cout << "Cannot authentificate client\n";
      if(sockServer)
      {
        ::DeleteSecurityContext(&g_hContext);
        ::FreeCredentialsHandle(&g_hCred);
        shutdown(sockServer, 2);
      }
      continue;
    }

    // workflow
    char cHello[] = "Hello to Client!!!";
    bool fResult = sendEncrypted(
      sockServer,
      cHello,
      sizeof(cHello));
    if(!fResult)
    {
      std::cout << "Error in sendEncrypted\n";
    }

    char cBuf[500] = "";
    size_t szReceived = 0;
    fResult = receiveEncrypted(
      sockServer,
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

    long lDecryptReturn = 0;
    fResult = receiveEncrypted(
      sockServer,
      cBuf,
      500,
      szReceived,
      &lDecryptReturn);
    if(!fResult)
    {
      std::cout << "Error in receiveEncrypted\n";
    }
    if(lDecryptReturn)
    {
      std::cout << "Client disconnected\n\n";
      shutdownChannel(sockServer, false);
    }

    if(sockServer)
    {
      ::DeleteSecurityContext(&g_hContext);
      ::FreeCredentialsHandle(&g_hCred);
      shutdown(sockServer, 2);
    }
  }

  std::cout << "Test finished\n";
  cleanup();
  system("pause");
  return 0;
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