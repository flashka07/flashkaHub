#include "iSchannelUtils.h"

#include <Windows.h>
#include <stdio.h>

void ISchannelUtils::printHexDump(
  size_t aszLength, 
  const void* apBuffer)
{
  const BYTE* buffer = reinterpret_cast<const BYTE*>(apBuffer);
  DWORD i,count,index;
  CHAR rgbDigits[]="0123456789abcdef";
  CHAR rgbLine[100];
  char cbLine;

  for(index = 0; aszLength;
     aszLength -= count, buffer += count, index += count) 
  {
     count = (aszLength > 16) ? 16:aszLength;

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