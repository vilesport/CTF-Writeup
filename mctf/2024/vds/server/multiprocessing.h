#include <stdint.h>

#ifndef PROCESSING
#define PROCESSING

void install_seccompx();

void spawn_child(bool is_privildeged,void(*handler)());

#endif
