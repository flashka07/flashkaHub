#include <iostream>
#include <map>
#include <string>

#include "aes_test.h"
#include "sha1_test.h"
#include "byteSeq_test.h"

typedef void (*TestProc)();
std::map<std::string, TestProc> g_testProcMap; 

void initList()
{
  g_testProcMap["aes"] = aes::test_aes;
  g_testProcMap["sha1"] = sha1::test_sha1;
  g_testProcMap["byte"] = byteseq::test_byteSeq;
}

void printList()
{
  if(!g_testProcMap.size())
  {
    std::cout << "(Empty commands list)\n";
    return;
  }

  for(std::map<std::string, TestProc>::const_iterator i = g_testProcMap.begin();
      i != g_testProcMap.end();
      ++i)
  {
    std::cout << i->first << '\n';
  }
}

bool launchCommand(const std::string& astrCommand)
{
  std::map<std::string, TestProc>::const_iterator iCmd =
    g_testProcMap.find(astrCommand);

  if(iCmd != g_testProcMap.end())
  {
    iCmd->second();
    return true;
  }

  return false;
}

void main()
{
  unsigned char a = 0x02;
  unsigned char b = a << -1;
  std::cout << (unsigned int)a << '\n'
    << (unsigned int)b << '\n';

  initList();

  std::cout << "Type one command from list\n";
  printList();
  std::cout << "Command: ";
  std::string strCommand;
  std::cin >> strCommand;
  std::cout << '\n';

  if(!launchCommand(strCommand))
    std::cout << "Command \"" << strCommand << "\" not found\n";

  std::cout << '\n';
  std::system("pause");	
}