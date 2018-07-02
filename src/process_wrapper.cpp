#include "process_wrapper.h"

#include <stdlib.h>

namespace sniffer {

ProcessWrapper::ProcessWrapper() {
  ReadConfig(GetConfigPath());
}

int ProcessWrapper::Exec(int argc, char** argv) {
  return EXIT_SUCCESS;
}

int ProcessWrapper::SendStopDaemonRequest() {
  return EXIT_SUCCESS;
}

common::file_system::ascii_file_string_path ProcessWrapper::GetConfigPath() {
  return common::file_system::ascii_file_string_path(CONFIG_FILE_PATH);
}

void ProcessWrapper::ReadConfig(const common::file_system::ascii_file_string_path& config_path) {
  common::Error err = load_config_file(config_path, &config_);
  if (err) {
    ERROR_LOG() << "Can't open config file path: " << config_path.GetPath() << ", error: " << err->GetDescription();
  }
}
}
