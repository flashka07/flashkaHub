#include <memory>
#include <ctime>
#include "apollo_test.h"

#include "../SChannel/tCryptProv.h"

#include "../SChannel/iSocket.h"
//#include "../SChannel/iSocketStream.h"

#include "../SChannel/iCertificate.h"
#include "../SChannel/iCertificateUtils.h"
#include "../SChannel/iSchannelUtils.h"
#include "../SChannel/iLog.h"

#pragma comment(lib, "Ws2_32.lib")

namespace apollo
{
  const size_t szBlockSize = 16;

  void generateData(size_t aszLength, TBlob& aBuffer);

  int testBufferCrypt(
    HCRYPTKEY ahKey,
    size_t aszBlocksCount);

  int testBufferSign(
    const ICertificate& aCert,
    size_t aszMsgSize);

  int tcp_encrypt(
    HCRYPTKEY ahKey,
    TEncryptState& state,
    const TBlob& plaintext, 
    TBlob& aCiphertext);

  int tcp_decrypt(
    HCRYPTKEY ahKey, 
    TEncryptState& state,
    const TBlob& ciphertext, 
    TBlob& aPlaintext);



  void test_apollo()
  {
    std::string strAddress("192.168.0.164");
    std::string strPort("5001");
    /*ILog("Input destination address and port:");
    std::cin >> strAddress >> strPort;*/

    ILog(ISchannelUtils::printError(
      cryptoaes_test()));

    ILog(ISchannelUtils::printError(
      cryptosign_test()));

    ILog(ISchannelUtils::printError(
      aesCBF_test()));

    ILog(ISchannelUtils::printError(
      encrypt_test(
        strAddress,
        strPort)));
  }


  int cryptoaes_test()
  {
    ILog("\nCrypto AES-256 ecryption test\n");
    // prepare crypt
    TCryptProv cryptProv(L"AESCrypt");

    const size_t c_szKeyLength = 32;
    const BYTE c_Key[c_szKeyLength] = 
    {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    TBlob vKey(c_Key, c_Key + c_szKeyLength);
    HCRYPTKEY hKey = NULL;
    int nResult = ISchannelUtils::importAES256Key(
      cryptProv,
      vKey,
      hKey);
    if(nResult)
    {
      ILogR("Error in importAES256Key", nResult);
      return nResult;
    }
    
    srand(std::time(0));
    TBlob iters;
    for(int i=0; i<10; ++i)
    {
      generateData(1, iters);
      nResult = testBufferCrypt(hKey, iters[0]);
      if(nResult)
      {
        ILogR("Error in testBufferCrypt", nResult);
        break;
      }
    }
    ::CryptDestroyKey(hKey);

    /*std::string strData("Test string!");
    ILog("String to encrypt: " + strData);

    TBlob toEncrypt(strData.begin(), strData.end());
    TBlob encrypted;
    nResult = ISchannelUtils::encryptAES256(
      hKey,
      toEncrypt,
      encrypted);
    if(nResult)
    {
      ILogR("Error in encryptAES256", nResult);
      ::CryptDestroyKey(hKey);
      return nResult;
    }

    ILog("Encrypted: ");
    ISchannelUtils::printHexDump(
      encrypted.size(), 
      &encrypted.front());

    TBlob decrypted;
    nResult = ISchannelUtils::decryptAES256(
      hKey,
      encrypted,
      decrypted);
    if(nResult)
    {
      ILogR("Error in decryptAES256", nResult);
      ::CryptDestroyKey(hKey);
      return nResult;
    }
    ::CryptDestroyKey(hKey);

    std::string strDecrypted(
      decrypted.begin(),
      decrypted.end());
    ILog("Decrypted string: " + strDecrypted);*/

    return 0;
  }

  int cryptosign_test()
  {
    ILog("\nCrypto Sign and verify test\n");

    std::auto_ptr<ICertificate> spCert(
      ICertificate::create());
    if(!spCert.get())
    {
      ILog("Cannot create certificate");
      return -5;
    }

    srand(std::time(0));
    TBlob iters;
    int nResult = 0;
    for(int i=0; i<10; ++i)
    {
      generateData(1, iters);
      nResult = testBufferSign(*spCert, iters[0]);
      if(nResult)
      {
        ILogR("Error in testBufferCrypt", nResult);
        break;
      }
    }

    return nResult;
  }

  void generateData(size_t aszLength, TBlob& aBuffer)
  {
    aBuffer.resize(aszLength);
    for(size_t i=0; i<aszLength; ++i)
    {
      aBuffer[i] = rand() % 256;
    }
  }

  int testBufferCrypt(
    HCRYPTKEY ahKey,
    size_t aszBlocksCount)
  {
    std::stringstream strs;
    strs << "Crypt test: " << aszBlocksCount << " blocks";
    ILog(strs.str());

    TBlob source;
    generateData(aszBlocksCount * szBlockSize, source);

    TBlob encrypted;
    int nResult = ISchannelUtils::encryptAES256(
      ahKey,
      source,
      encrypted);
    if(nResult)
    {
      ILogR("Error in encryptAES256", nResult);
      return nResult;
    }

    TBlob decrypted;
    nResult = ISchannelUtils::decryptAES256(
      ahKey,
      encrypted,
      decrypted);
    if(nResult)
    {
      ILogR("Error in decryptAES256", nResult);
      return nResult;
    }

    if(source == decrypted)
      ILog("\t...Passed")
    else
      ILog("\t...Failed")

    return 0;
  }

  int testBufferSign(
    const ICertificate& aCert,
    size_t aszMsgSize)
  {
    std::stringstream strs;
    strs << "Sign test: " << aszMsgSize << " bytes of message";
    ILog(strs.str());

    TBlob vData;
    generateData(aszMsgSize, vData);

    TBlob vSigned;
    int nResult = ICertificateUtils::signHashMessage(
      vData,
      aCert,
      vSigned);
    if(nResult)
    {
      ILogR("Error in signHashMessage", nResult);
      return nResult;
    }

    nResult = ICertificateUtils::verifyHashMessage(
      vSigned, 
      aCert,
      vData);
    if(nResult)
    {
      ILogR("Error in verifyHashMessage", nResult);
      ILog("\t...Failed")
    }

    ILog("\t...Passed");
    return 0;
  }

  int aesCBF_test()
  {
    ILog("\nCrypto AES-256 CBF ecryption test\n");

    // prepare crypt
    TCryptProv cryptProv(L"AESCrypt");
    HCRYPTKEY hKey = NULL;
    TEncryptState encState;
    TEncryptState decState;

    if(true)
    {
      const size_t c_szKeyLength = 32;
      const BYTE c_Key[c_szKeyLength] = 
      {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      };

      TBlob vKey(c_Key, c_Key + c_szKeyLength);
    
      int nResult = ISchannelUtils::importAES256Key(
        cryptProv,
        vKey,
        hKey);
      if(nResult)
      {
        ILogR("Error in importAES256Key", nResult);
        return nResult;
      }

      // set Key mode to CBF
      DWORD dwParam = CRYPT_MODE_ECB;
      BOOL fResult = ::CryptSetKeyParam(
        hKey,
        KP_MODE,
        (BYTE*)&dwParam,
        0);
      if(!fResult)
      {
        nResult = ::GetLastError();
        ILogR("Error in ::CryptSetKeyParam", nResult);
        ::CryptDestroyKey(hKey);
        return nResult;
      }

      const BYTE initVector[16] = 
      {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
      };

      encState.iv.assign(initVector, initVector + sizeof(initVector));
      encState.bPos = 0;
      decState = encState;
    }

    TBlob bSource(1, 0);
    ILog("Source:");
    ISchannelUtils::printHexDump(bSource.size(), &bSource.front());

    TBlob encrypted;
    int nResult = tcp_encrypt(
      hKey,
      encState,
      bSource,
      encrypted);
    if(nResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in tcp_encrypt", nResult);
      ::CryptDestroyKey(hKey);
      return nResult;
    }

    ILog("Encrypted:");
    ISchannelUtils::printHexDump(encrypted.size(), &encrypted.front());

    TBlob decrypted;
    nResult = tcp_decrypt(
      hKey,
      decState,
      encrypted,
      decrypted);
    if(nResult)
    {
      nResult = ::GetLastError();
      ILogR("Error in tcp_decrypt", nResult);
      ::CryptDestroyKey(hKey);
      return nResult;
    }

    ILog("Decrypted:");
    ISchannelUtils::printHexDump(decrypted.size(), &decrypted.front());

    return 0;
  }
  
  int encrypt_test(
    const std::string& astrAddress,
    const std::string& astrPort)
  {
    ILog("\nApollo ecryption test\n");

    bool fUseEncryption = true;

    // connect to socket
    std::auto_ptr<ISocket> spSocket(ISocket::create());
    if(!spSocket.get())
    {
      ILog("Cannot create socket");
      return -5;
    }

    int nResult = spSocket->connect(
      astrAddress,
      astrPort);
    if(nResult)
    {
      ILogR("Error in spSocket->connect", nResult);
      return nResult;
    }

    // prepare crypt
    TCryptProv cryptProv(L"AESCrypt");
    HCRYPTKEY hKey = NULL;
    TEncryptState encState;
    TEncryptState decState;

    if(fUseEncryption)
    {
      const size_t c_szKeyLength = 32;
      const BYTE c_Key[c_szKeyLength] = 
      {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      };

      TBlob vKey(c_Key, c_Key + c_szKeyLength);
    
      nResult = ISchannelUtils::importAES256Key(
        cryptProv,
        vKey,
        hKey);
      if(nResult)
      {
        ILogR("Error in importAES256Key", nResult);
        return nResult;
      }

      // set Key mode to CBF
      DWORD dwParam = CRYPT_MODE_ECB;
      BOOL fResult = ::CryptSetKeyParam(
        hKey,
        KP_MODE,
        (BYTE*)&dwParam,
        0);
      if(!fResult)
      {
        nResult = ::GetLastError();
        ILogR("Error in ::CryptSetKeyParam", nResult);
        ::CryptDestroyKey(hKey);
        return nResult;
      }

      const BYTE initVector[16] = 
      {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
      };

      encState.iv.assign(initVector, initVector + sizeof(initVector));
      encState.bPos = 0;
      decState = encState;

      /*fResult = ::CryptSetKeyParam(
        hKey,
        KP_IV,
        initVector,
        0);
      if(!fResult)
      {
        nResult = ::GetLastError();
        ILogR("Error in ::CryptSetKeyParam", nResult);
        ::CryptDestroyKey(hKey);
        return nResult;
      }*/

      // send initVector
      nResult = sendBytes(
        spSocket->getInnerSocket(),
        initVector,
        sizeof(initVector));
      if(nResult)
      {
        ILogR("Cannot send initVector", nResult);
        return nResult;
      }
      
      ILog("Sent IV:");
      ISchannelUtils::printHexDump(
        sizeof(initVector), 
        initVector);
    }

    // main loop
    const unsigned int c_unTimeOut = 2000;
    TBlob vInputBuffer(0xff);
    int i = 8;
    while(true)
    {
      size_t szRead = 0;
      nResult = receiveBytes(
        spSocket->getInnerSocket(),
        &vInputBuffer.front(),
        vInputBuffer.size(),
        szRead,
        c_unTimeOut);
      if(nResult)
      {
        ILogR("Cannot receive bytes", nResult);
        return nResult;
      }

      if(szRead)
      {
        TBlob vMessage(szRead);
        std::copy(
          vInputBuffer.begin(),
          vInputBuffer.begin() + szRead,
          vMessage.begin());
        ILog("Reived bytes:");
        ISchannelUtils::printHexDump(vMessage.size(), &vMessage.front());

        if(fUseEncryption)
        {
          /*size_t szMsg = ((vMessage.size() + 16 - 1) / 16) * 16;
          vMessage.resize(szMsg);*/
          nResult = tcp_decrypt(hKey, decState, vMessage, vMessage);
          if(nResult)
          {
            ILogR("Cannot decrypt bytes", nResult);
            return nResult;
          }
          ILog("Reived message:");
          ISchannelUtils::printHexDump(vMessage.size(), &vMessage.front());
        }
      }

      if(!(i--))
        break;

      // send data
      TBlob vToSend(1, 0);
      if(fUseEncryption)
      {
        vToSend.resize(2);
        nResult = tcp_encrypt(
          hKey,
          encState,
          vToSend,
          vToSend);
        if(nResult)
        {
          ILogR("Cannot encrypt bytes", nResult);
          return nResult;
        }
      }
      nResult = sendBytes(
        spSocket->getInnerSocket(),
        &vToSend.front(),
        vToSend.size());
      if(nResult)
      {
        ILogR("Cannot send bytes", nResult);
        return nResult;
      }
      ILog("Sent bytes:");
      ISchannelUtils::printHexDump(vToSend.size(), &vToSend.front());
    }
    return 0;
  }

  int sendBytes(
    SOCKET aSocket,
    const void* apBuf, 
    size_t aszBuf)
  {
    long int lnRemaining = aszBuf;

    while(lnRemaining) 
    {
      ILog("+ Sending");
      int nSent = ::send(
        aSocket, 
        reinterpret_cast<const char*>(apBuf), 
        lnRemaining, 
        0);
      if(SOCKET_ERROR == nSent) 
      {
        int nResult = ::WSAGetLastError();
        ILogR("error in ::send", nResult);
        return nResult;
      }

      apBuf = reinterpret_cast<const char*>(apBuf) + nSent;
      lnRemaining -= nSent;
    }

    return 0;
  }

  int receiveBytes(
    SOCKET aSocket,
    void* apBuf, 
    size_t aszBuf, 
    size_t& aszRead,
    unsigned int aunTimeout)
  {  
    long int lnRemaining = aszBuf;

    while(lnRemaining) 
    {
      ILog("- Receiving");
      if(aunTimeout)
      {
        fd_set fdsRead = {0};
        FD_SET(aSocket, &fdsRead);
        TIMEVAL interval = {0};
        interval.tv_sec = aunTimeout / 1000; // from ms to s
        interval.tv_usec = (aunTimeout % 1000) * 1000; // from ms to us (micro)

        int nResult = ::select(
          0,
          &fdsRead,
          NULL,
          NULL,
          &interval);
        if(nResult == SOCKET_ERROR)
        {
          nResult = ::WSAGetLastError();
          ILogR("Cannot shutdown socket", nResult);
          return nResult;
        }
        if(!nResult)
        {
          aszRead = aszBuf - lnRemaining;
          return 0; // timeout
        }
      }

      int nRead = ::recv(
        aSocket, 
        reinterpret_cast<char*>(apBuf), 
        lnRemaining, 
        0);
      if(SOCKET_ERROR == nRead) 
      {
        int nResult = ::WSAGetLastError();
        ILogR("error in ::recv", nResult);
        return nResult;
      }

      lnRemaining -= nRead;
      apBuf = reinterpret_cast<char*>(apBuf) + nRead;
    }

    aszRead = aszBuf - lnRemaining;
    return 0;
  }

  int tcp_encrypt(
    HCRYPTKEY ahKey,
    TEncryptState& state,
    const TBlob& plaintext, 
    TBlob& aCiphertext)
  {
    TBlob ciphertext(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i++) {
      if (state.bPos == 0) {
        //blockEncrypt(ive, shared_key, 0, ive, (method - 1));
        int nResult = ISchannelUtils::encryptAES256(
          ahKey,
          state.iv,
          state.iv);
        if(nResult)
        {
          ILogR("Error in encryptAES256", nResult);
          return nResult;
        }
        state.bPos = 16;
      }
      state.iv[16 - state.bPos] ^= plaintext[i];
      ciphertext[i] = state.iv[16 - state.bPos];
      state.bPos--;
    }
    aCiphertext.swap(ciphertext);
    return 0;
  }

  int tcp_decrypt(
    HCRYPTKEY ahKey,
    TEncryptState& state,
    const TBlob& ciphertext, 
    TBlob& aPlaintext)
  {
    TBlob plaintext(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); i++) {
      if (state.bPos == 0) {
        //blockEncrypt(ivd, shared_key, 0, ivd, (method - 1));
        int nResult = ISchannelUtils::encryptAES256(
          ahKey,
          state.iv,
          state.iv);
        if(nResult)
        {
          ILogR("Error in encryptAES256", nResult);
          return nResult;
        }
        state.bPos = 16;
      }
      plaintext[i] = state.iv[16 - state.bPos] ^ ciphertext[i];
      state.iv[16 - state.bPos] = ciphertext[i];
      state.bPos--;
    }
    aPlaintext.swap(plaintext);
    return 0;
  }
}