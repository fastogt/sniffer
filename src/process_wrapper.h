#pragma once

namespace sniffer {

class ProcessWrapper {
 public:
  ProcessWrapper();
  int Exec(int argc, char** argv);

  static int SendStopDaemonRequest();
};
}
