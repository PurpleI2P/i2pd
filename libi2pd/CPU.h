#ifndef LIBI2PD_CPU_H
#define LIBI2PD_CPU_H

namespace i2p
{
namespace cpu
{
  extern bool aesni;
  extern bool avx;

  void Detect();
}
}

#endif
