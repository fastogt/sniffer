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

#pragma once

#include <string>  // for string

#include <common/error.h>      // for Error
#include <common/macros.h>     // for WARN_UNUSED_RESULT
#include <common/net/types.h>  // for HostAndPort
#include <common/file_system/path.h>

namespace sniffer {
namespace client {

struct ServerSettings {
  ServerSettings();
  std::string id;
  common::net::HostAndPort master_node_host;
  std::string device;
};

struct Config {
  Config();

  ServerSettings server;
};

common::Error load_config_file(const common::file_system::ascii_file_string_path& config_path, Config* options) WARN_UNUSED_RESULT;
common::Error save_config_file(const common::file_system::ascii_file_string_path& config_path, Config* options) WARN_UNUSED_RESULT;

}
}
