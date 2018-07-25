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

#include "client/config.h"

#include <string.h>  // for strcmp

#include <common/logger.h>  // for COMPACT_LOG_WARNING, WARNING_LOG
#include <common/string_util.h>

#include "inih/ini.h"

#define CONFIG_SERVER "server"
#define CONFIG_SERVER_ID_FIELD "id"
#define CONFIG_SERVER_DEVICE_FIELD "device"

#define CONFIG_MASTER "master"
#define CONFIG_MASTER_NODE_HOST_FIELD "node_host"
#define CONFIG_MASTER_NODE_LICENSE_KEY_FIELD "node_license_key"

#define DEFAULT_MASTER_NODE_PORT_FIELD 6317

namespace {
const char kDefaultID[] = "localhost";
const common::net::HostAndPort kDefaultMasterNodeHost =
    common::net::HostAndPort::CreateLocalHost(DEFAULT_MASTER_NODE_PORT_FIELD);
const char kDefaultDevice[] = "eth0";
const char kDefaultMasterNodeLicenseKey[] = LICENSE_KEY;
}
/*
  [server]
  id=localhost
  device=eth0

  [master]
  node_host=localhost:6317
  node_license_key=0e4eb3ea92572a4ad627ad27e4a2c14d43a08a12ab25f8d288e33408f071dd0c
*/

#define MATCH_FIELD(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

namespace sniffer {
namespace client {
namespace {
int ini_handler_fasto(void* user_data, const char* section, const char* name, const char* value) {
  Config* pconfig = reinterpret_cast<Config*>(user_data);
  if (MATCH_FIELD(CONFIG_SERVER, CONFIG_SERVER_ID_FIELD)) {
    pconfig->server.id = value;
    return 1;
  } else if (MATCH_FIELD(CONFIG_SERVER, CONFIG_SERVER_DEVICE_FIELD)) {
    pconfig->server.device = value;
    return 1;
  } else if (MATCH_FIELD(CONFIG_MASTER, CONFIG_MASTER_NODE_HOST_FIELD)) {
    common::net::HostAndPort hs;
    if (common::ConvertFromString(value, &hs)) {
      pconfig->master.node_host = hs;
    }
    return 1;
  } else if (MATCH_FIELD(CONFIG_MASTER, CONFIG_MASTER_NODE_LICENSE_KEY_FIELD)) {
    pconfig->master.node_license_key = value;
    return 1;
  } else {
    return 0; /* unknown section/name, error */
  }
}
}  // namespace

ServerSettings::ServerSettings() : id(kDefaultID), device(kDefaultDevice) {}

MasterSettings::MasterSettings() : node_host(kDefaultMasterNodeHost), node_license_key(kDefaultMasterNodeLicenseKey) {}

Config::Config() : server() {}

common::Error load_config_file(const common::file_system::ascii_file_string_path& config_path, Config* options) {
  if (!options || !config_path.IsValid()) {
    return common::make_error_inval();
  }

  std::string path = config_path.GetPath();
  ini_parse(path.c_str(), ini_handler_fasto, options);
  return common::Error();
}

common::Error save_config_file(const common::file_system::ascii_file_string_path& config_path, Config* options) {
  if (!options || !config_path.IsValid()) {
    return common::make_error_inval();
  }

  NOTREACHED() << "Not implemeted.";
  return common::Error();
}
}
}
