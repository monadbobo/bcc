#include "cc/bpf_module.h"
#include "cc/bpf_common.h"

extern "C" {
void * bpf_module_create(const char *filename, const char *proto_filename, unsigned flags) {
  auto mod = new ebpf::BPFModule(flags);
  if (mod->load(filename, proto_filename) != 0) {
    delete mod;
    return nullptr;
  }
  return mod;
}

void * bpf_module_create_from_string(const char *text, unsigned flags) {
  auto mod = new ebpf::BPFModule(flags);
  if (mod->load_string(text) != 0) {
    delete mod;
    return nullptr;
  }
  return mod;
}

void bpf_module_destroy(void *program) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return;
  delete mod;
}

void * bpf_function_start(void *program, const char *name) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return nullptr;
  return mod->start(name);
}

size_t bpf_function_size(void *program, const char *name) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return 0;
  return mod->size(name);
}

char * bpf_module_license(void *program) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return nullptr;
  return mod->license();
}

unsigned bpf_module_kern_version(void *program) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return 0;
  return mod->kern_version();
}

int bpf_table_fd(void *program, const char *table_name) {
  auto mod = static_cast<ebpf::BPFModule *>(program);
  if (!mod) return -1;
  return mod->table_fd(table_name);
}

}