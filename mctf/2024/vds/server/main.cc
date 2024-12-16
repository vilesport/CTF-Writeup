#include <iostream>
#include <fcntl.h>
#include "vds.h"
#include "multiprocessing.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>

void child()  {
  void (*prog)() = (void(*)())mmap(0, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  std::cout<<"Welcome to your vds vm!!!\n";
  std::cout<<"Enter your program x86_64 source.\n";
  std::cout<<">>\n";
  fgets((char*)prog,0x4000,stdin);
  prog();
  std::cout<<"Finished execution!!!\n";
  exit(0);
}

void menu() {
  std::cout<<"Enter 1 to spawn your vm instance.\n";
  std::cout<<"Enter 2 to exit vds manager\n";
}

int main() {
  char buf[10] = {0};
  std::cout<<"Vds server activated."<<"\n";
  int option = 0;
  while(true) {
    menu();
    fgets(buf,10,stdin);
    option = atoi(buf);
    switch(option){
      case 1:
        spawn_child(false, child);
        break;
      case 2:
        exit(0);
      break;
      default:
        std::cout<<"Invalid option\n";
      break;
    }
  }
  return 0;
}
