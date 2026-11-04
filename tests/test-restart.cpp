#include "api.h"
#include <vector>

using namespace i2p::api;

int main(){
  // Cleaning the dir does not fix this issue
  std::vector<const char*> argv({"i2pouiservice", "--datadir=/tmp/mewmew"});

  InitI2P(argv.size(), (char**) argv.data(), argv[0]);
  // Commented lines below do not provide necessary cleanup
  // uncomment to see that error persists
  // StopI2P();
  // TerminateI2P();

  // This fails with ambiguous option error on parsing
  // the exact same commandline as before
  InitI2P(argv.size(), (char**) argv.data(), argv[0]);

  // No asserts needed, it crashes
}
