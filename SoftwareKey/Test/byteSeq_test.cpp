#include <iostream>
#include <ctime>
#include "byteSeq_test.h"
#include "byteSeq.h"

namespace byteseq
{
  void test_byteSeq()
  {
    std::cout << "test_byteSeq:\n";
    ByteSeq a(0x05);
    ByteSeq b(0x01);
    ByteSeq c = a - b;
    std::cout << a << " - " << b << " = " << c << '\n';

    ByteSeq d = 0x00ff00aa;
    std::cout << d << " + " << d << " = " << d + d << '\n';
    d = 0xffffffff;
    std::cout << d << " + 1 = " << d + 1 << '\n';

    d = d + 1;
    std::cout << d << " + 1 = " << d + 1 << '\n';

    c = 0xffffffff;
    c = c + c;
    std::cout << c << " + " << c << " = " << c + c << '\n';

    ByteSeq e(0x0f);
    std::cout << e << " - " << 0xff << " = " << e - 0xff << '\n';

    sum_test();
    mul_test();
    shift_test();
    bitwise_test();
  }

  bool sum_test()
  {
    std::cout << "\nsum_test:\n";
    
    srand(std::time(0));
    for(int i=0; i<10; ++i)
    {
      BYTE ba = rand() % 256;
      BYTE bb = rand() % 256;
      ByteSeq a(ba);
      ByteSeq b(bb);
      DWORD bc = (DWORD)ba + (DWORD)bb;
      BYTE bd = (DWORD)ba - (DWORD)bb;
      ByteSeq c = a + b;
      ByteSeq d = a - b;

      std::cout << std::hex << a << " + " << b << " = " 
        << c << ". Must be " << bc << " :: "
        << ((c == bc) ? "TRUE" : "FALSE") << '\n';
      std::cout << std::hex << a << " - " << b << " = " 
        << d << ". Must be " << (DWORD)bd << " :: "
        << ((d == bd) ? "TRUE" : "FALSE") << '\n';
    }
    return true;
  }

  bool mul_test()
  {
    std::cout << "\nmul_test:\n";
    srand(std::time(0));
    for(int i=0; i<10; ++i)
    {
      WORD ba = rand() % 0xffff;
      WORD bb = rand() % 0xffff;
      ByteSeq a(ba);
      ByteSeq b(bb);
      DWORD bc = ba * bb;
      //BYTE bd = (DWORD)ba - (DWORD)bb;
      ByteSeq c = a * b;
      //ByteSeq d = a - b;

      std::cout << std::hex << a << " * " << b << " = " 
        << c << ". Must be " << bc << " :: "
        << ((c == bc) ? "TRUE" : "FALSE") << '\n';
      /*std::cout << std::hex << a << " - " << b << " = " 
        << d << ". Must be " << (DWORD)bd << " :: "
        << ((d == bd) ? "TRUE" : "FALSE") << '\n';*/
    }

    DWORD ba = 0xabcd1234;
    WORD bb = 0x1234;
    ByteSeq a(ba);
    ByteSeq b(bb);
    DWORD bc = ba / bb;
    DWORD br = ba % bb;
    ByteSeq r;
    a.divideBy(b, &r);

    std::cout << std::hex << ByteSeq(ba) << " / " << b << " = " 
      << a << " + " << r << ". Must be " << bc << " + " << br << " :: "
      << ((a == bc && r == br) ? "TRUE" : "FALSE") << '\n';

    ba = 0xabcd1234;
    bb = 0x12;
    a = ba;
    b = bb;
    bc = ba / bb;
    br = ba % bb;
    a.divideBy(b, &r);

    std::cout << std::hex << ByteSeq(ba) << " / " << b << " = " 
      << a << " + " << r << ". Must be " << bc << " + " << br << " :: "
      << ((a == bc && r == br) ? "TRUE" : "FALSE") << '\n';

    ba = 0x1234;
    bb = 0xab;
    a = ba;
    b = bb;
    bc = ba / bb;
    br = ba % bb;
    a.divideBy(b, &r);

    std::cout << std::hex << ByteSeq(ba) << " / " << b << " = " 
      << a << " + " << r << ". Must be " << bc << " + " << br << " :: "
      << ((a == bc && r == br) ? "TRUE" : "FALSE") << '\n';

    ba = 0x1234;
    bb = 0xff;
    a = ba;
    b = bb;
    bc = ba / bb;
    br = ba % bb;
    a.divideBy(b, &r);

    std::cout << std::hex << ByteSeq(ba) << " / " << b << " = " 
      << a << " + " << r << ". Must be " << bc << " + " << br << " :: "
      << ((a == bc && r == br) ? "TRUE" : "FALSE") << '\n';

    ba = 0xce;
    bb = 0xa0;
    a = ba;
    b = bb;
    bc = ba / bb;
    br = ba % bb;
    a.divideBy(b, &r);

    std::cout << std::hex << ByteSeq(ba) << " / " << b << " = " 
      << a << " + " << r << ". Must be " << bc << " + " << br << " :: "
      << ((a == bc && r == br) ? "TRUE" : "FALSE") << '\n';

    return true;
  }

  bool shift_test()
  {
    std::cout << "\nshift_test:\n";
    ByteSeq a(BYTE(1));
    for(int i=0; i<32; ++i)
    {
      ByteSeq b(a);
      b.shiftLeft(i);
      std::cout << std::hex << a << " << " << i 
        << " = " << b << '\n';
    }
    a = 0x80000000;
    for(int i=0; i<32; ++i)
    {
      ByteSeq b(a);
      b.shiftRight(i);
      std::cout << std::hex << a << " >> " << i 
        << " = " << b << '\n';
    }
    return true;
  }

  bool bitwise_test()
  {
    srand(std::time(0));
    for(int i=0; i<5; ++i)
    {
      DWORD ba = ((rand() % 0x00010000) << 16) + (rand() % 0x00010000);
      WORD bb = (rand() % 0x00010000);
      ByteSeq a(ba);
      ByteSeq b(bb);
      DWORD bc = ba & bb;
      DWORD bd = ba | bb;
      DWORD be = ba ^ bb;
      DWORD bf = ~ba;
      ByteSeq c = a & b;
      ByteSeq d = a | b;
      ByteSeq e = a ^ b;
      ByteSeq f = ~a;

      std::cout << std::hex << a << " & " << b << " = " 
        << c << ". Must be " << bc << " :: "
        << ((c == bc) ? "TRUE" : "FALSE") << '\n';
      std::cout << std::hex << a << " | " << b << " = " 
        << d << ". Must be " << (DWORD)bd << " :: "
        << ((d == bd) ? "TRUE" : "FALSE") << '\n';
      std::cout << std::hex << a << " ^ " << b << " = " 
        << e << ". Must be " << (DWORD)bd << " :: "
        << ((e == be) ? "TRUE" : "FALSE") << '\n';
      std::cout << std::hex << " ~ " << a << " = " 
        << f << ". Must be " << (DWORD)bf << " :: "
        << ((f == bf) ? "TRUE" : "FALSE") << '\n';
    }
    return true;
  }
}