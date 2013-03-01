#pragma once
#include <iostream>
#include <string>
#include <sstream>

#define ILog(text) { std::cout << (text) << '\n'; }
#define ILogR(text, code) { std::cout << std::hex << (text) << " = " << (code) << '\n'; }
