#include <string>
#include <stdint.h>
#include "multiprocessing.h"
#include <vector>

#ifndef VDS
#define VDS

struct vds_user {
  vds_user(std::string& name,uint32_t id,bool is_admin);
  std::string name;
  uint32_t id =0xffffffff;
  bool is_admin = 0;
};

class vds_system {
  public:
    void add_user(vds_user& user);
    void delete_user(uint32_t id);
    void run_vm(uint32_t id);
  private:
    std::vector<vds_user> users;
};

#endif
