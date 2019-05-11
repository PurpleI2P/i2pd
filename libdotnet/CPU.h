#ifndef LIBDOTNET_CPU_H
#define LIBDOTNET_CPU_H

namespace dotnet
{
namespace cpu
{
  extern bool aesni;
  extern bool avx;

  void Detect();
}
}

#endif
