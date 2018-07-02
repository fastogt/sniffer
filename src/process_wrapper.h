#pragma once

#include <string>

#include "config.h"

namespace sniffer {

class ProcessWrapper {
 public:
  ProcessWrapper();
  int Exec(int argc, char** argv);

  static int SendStopDaemonRequest();
  static common::file_system::ascii_file_string_path GetConfigPath();

 private:
  void ReadConfig(const common::file_system::ascii_file_string_path& config_path);

  Config config_;
};
}
