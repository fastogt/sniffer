/*  Copyright (C) 2014-2018 FastoGT. All right reserved.
    This file is part of sniffer.
    sniffer is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    sniffer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with sniffer.  If not, see <http://www.gnu.org/licenses/>.
*/

// https://stackoverflow.com/questions/39456131/improve-insertion-time-in-cassandra-database-with-datastax-cpp-driver

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>

#include <common/file_system/file.h>
#include <common/file_system/file_system.h>
#include <common/file_system/string_path_utils.h>
#include <common/utils.h>
#include <common/license/gen_hardware_hash.h>

#include "client/process_wrapper.h"

#define HELP_TEXT                          \
  "Usage: " SERVICE_NAME                   \
  " [options]\n"                           \
  "  Manipulate " SERVICE_NAME             \
  ".\n\n"                                  \
  "    --version  display version\n"       \
  "    --daemon   run as a daemon\n"       \
  "    --stop     stop running instance\n" \
  "    --reload   force running instance to reread configuration file\n"

namespace {

bool create_license_key(std::string* license_key) {
#if HARDWARE_LICENSE_ALGO == 0
  static const common::license::ALGO_TYPE license_algo = common::license::HDD;
#elif HARDWARE_LICENSE_ALGO == 1
  static const common::license::ALGO_TYPE license_algo = common::license::MACHINE_ID;
#else
#error Unknown hardware license algo used
#endif

  if (!license_key) {
    return false;
  }

  if (SIZEOFMASS(LICENSE_KEY) == 1) {  // runtime check
    CRITICAL_LOG() << "A-a-a license key is empty, don't hack me!";
  }

  if (!common::license::GenerateHardwareHash(license_algo, license_key)) {
    WARNING_LOG() << "Failed to generate hash!";
    return false;
  }

  if (*license_key != LICENSE_KEY) {
    ERROR_LOG() << "License keys not same!";
    return false;
  }
  return true;
}
}  // namespace

int main(int argc, char** argv, char** envp) {
  bool run_as_daemon = false;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--version") == 0) {
      std::cout << PROJECT_VERSION_HUMAN << std::endl;
      return EXIT_SUCCESS;
    } else if (strcmp(argv[i], "--daemon") == 0) {
      run_as_daemon = true;
    } else if (strcmp(argv[i], "--stop") == 0) {
      std::string license_key;
      if (!create_license_key(&license_key)) {
        return EXIT_FAILURE;
      }

      return sniffer::client::ProcessWrapper::SendStopDaemonRequest(license_key);
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      std::cout << HELP_TEXT << std::endl;
      return EXIT_SUCCESS;
    } else {
      std::cout << HELP_TEXT << std::endl;
      return EXIT_FAILURE;
    }
  }

  if (run_as_daemon) {
    if (!common::create_as_daemon()) {
      return EXIT_FAILURE;
    }
  }

  pid_t daemon_pid = getpid();
  std::string folder_path_to_pid = common::file_system::get_dir_path(PIDFILE_PATH);
  if (folder_path_to_pid.empty()) {
    ERROR_LOG() << "Can't get pid file path: " << PIDFILE_PATH;
    return EXIT_FAILURE;
  }

  if (!common::file_system::is_directory_exist(folder_path_to_pid)) {
    if (!common::file_system::create_directory(folder_path_to_pid, true)) {
      ERROR_LOG() << "Pid file directory not exists, pid file path: " << PIDFILE_PATH;
      return EXIT_FAILURE;
    }
  }

  common::ErrnoError err = common::file_system::node_access(folder_path_to_pid);
  if (err) {
    ERROR_LOG() << "Can't have permissions to create, pid file path: " << PIDFILE_PATH;
    return EXIT_FAILURE;
  }

  common::file_system::File pidfile;
  err = pidfile.Open(PIDFILE_PATH, common::file_system::File::FLAG_CREATE | common::file_system::File::FLAG_WRITE);
  if (err) {
    ERROR_LOG() << "Can't open pid file path: " << PIDFILE_PATH;
    return EXIT_FAILURE;
  }

  err = pidfile.Lock();
  if (err) {
    ERROR_LOG() << "Can't lock pid file path: " << PIDFILE_PATH << "; message: " << err->GetDescription();
    return EXIT_FAILURE;
  }
  std::string pid_str = common::MemSPrintf("%ld\n", static_cast<long>(daemon_pid));
  size_t writed;
  err = pidfile.Write(pid_str, &writed);
  if (err) {
    ERROR_LOG() << "Failed to write pid file path: " << PIDFILE_PATH << "; message: " << err->GetDescription();
    return EXIT_FAILURE;
  }

// start
#if defined(NDEBUG)
  common::logging::LOG_LEVEL level = common::logging::LOG_LEVEL_INFO;
#else
  common::logging::LOG_LEVEL level = common::logging::LOG_LEVEL_DEBUG;
#endif
#if defined(LOG_TO_FILE)
  std::string log_path = common::file_system::prepare_path("/var/log/" PROJECT_NAME_LOWERCASE ".log");
  INIT_LOGGER(PROJECT_NAME_TITLE, log_path, level);
#else
  INIT_LOGGER(PROJECT_NAME_TITLE, level);
#endif

  std::string license_key;
  if (!create_license_key(&license_key)) {
    return EXIT_FAILURE;
  }

  sniffer::client::ProcessWrapper wrapper(license_key);
  NOTICE_LOG() << "Running " PROJECT_VERSION_HUMAN << " in " << (run_as_daemon ? "daemon" : "common") << " mode";

  for (char** env = envp; *env != NULL; env++) {
    char* cur_env = *env;
    INFO_LOG() << cur_env;
  }

  int res = wrapper.Exec(argc, argv);
  NOTICE_LOG() << "Quiting " PROJECT_VERSION_HUMAN;

  err = pidfile.Unlock();
  if (err) {
    ERROR_LOG() << "Failed to unlock pidfile: " << PIDFILE_PATH << "; message: " << err->GetDescription();
    return EXIT_FAILURE;
  }

  err = common::file_system::remove_file(PIDFILE_PATH);
  if (err) {
    WARNING_LOG() << "Can't remove file: " << PIDFILE_PATH << ", error: " << err->GetDescription();
  }
  return res;
}
