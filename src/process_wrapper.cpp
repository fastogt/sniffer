#include "process_wrapper.h"

#include <stdlib.h>

namespace sniffer {

ProcessWrapper::ProcessWrapper() {}

int ProcessWrapper::Exec(int argc, char** argv) {
  return EXIT_SUCCESS;
}

int ProcessWrapper::SendStopDaemonRequest() {
  return EXIT_SUCCESS;
}
}
