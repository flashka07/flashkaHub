#pragma once

class __declspec(dllexport) ISchannelUtils
{
public:
  static void printHexDump(
    size_t aszLength, 
    const void* apBuffer);
};