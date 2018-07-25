/*  Copyright (C) 2014-2018 FastoGT. All right reserved.
    This file is part of iptv_cloud.
    iptv_cloud is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    iptv_cloud is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with iptv_cloud.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "daemon_client/common_commands.h"

// activate
#define CLIENT_ACTIVATE_RESP_FAIL_1E GENEATATE_FAIL_FMT(CLIENT_ACTIVATE, "'%s'")
#define CLIENT_ACTIVATE_RESP_SUCCESS GENEATATE_SUCCESS(CLIENT_ACTIVATE)

// requests
// ping
#define CLIENT_PING_REQ GENERATE_REQUEST_FMT(CLIENT_PING)
#define CLIENT_PING_RESP_FAIL_1E GENEATATE_FAIL_FMT(CLIENT_PING, "'%s'")
#define CLIENT_PING_RESP_SUCCESS GENEATATE_SUCCESS(CLIENT_PING)

namespace sniffer {
namespace daemon_client {

protocol::responce_t ActivateResponceSuccess(protocol::sequance_id_t id) {
  return common::protocols::three_way_handshake::MakeResponce(id, CLIENT_ACTIVATE_RESP_SUCCESS);
}

protocol::request_t PingRequest(protocol::sequance_id_t id) {
  return common::protocols::three_way_handshake::MakeRequest(id, CLIENT_PING_REQ);
}

protocol::responce_t PingResponceSuccsess(protocol::sequance_id_t id) {
  return common::protocols::three_way_handshake::MakeResponce(id, CLIENT_PING_RESP_SUCCESS);
}

protocol::responce_t PingResponceFail(protocol::sequance_id_t id, const std::string& error_text) {
  return common::protocols::three_way_handshake::MakeResponce(id, CLIENT_PING_RESP_FAIL_1E, error_text);
}

}  // namespace server
}
