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

#include <stdlib.h>

#include "database/connection.h"

int main(int argc, char* argv[]) {
  const char* hosts = "127.0.0.1";
  if (argc > 1) {
    hosts = argv[1];
  }

  database::Connection con;
  common::Error err = con.Connect({hosts});
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    return EXIT_FAILURE;
  }

  auto cb = [](
      CassFuture* result_future) { /* Retrieve result set and get the first row */
                                   const CassResult* result = cass_future_get_result(result_future);
                                   const CassRow* row = cass_result_first_row(result);

                                   if (row) {
                                     const CassValue* value = cass_row_get_column_by_name(row, "release_version");

                                     const char* release_version;
                                     size_t release_version_length;
                                     cass_value_get_string(value, &release_version, &release_version_length);
                                     printf("release_version: '%.*s'\n", (int)release_version_length, release_version);
                                   }
  };

  err = con.Execute("SELECT release_version FROM system.local", 0, cb);
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    con.Disconnect();
    return EXIT_FAILURE;
  }

  con.Disconnect();
  return EXIT_SUCCESS;
}
