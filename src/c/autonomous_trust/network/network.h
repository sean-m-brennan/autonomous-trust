/********************
 *  Copyright 2024 TekFive, Inc. and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#ifndef NETWORK_H
#define NETWORK_H

#define COMM_PORT 27787
#define PING_RCV_PORT (COMM_PORT + 2)
#define PING_SND_PORT (PING_RCV_PORT + 1)
#define NTP_PORT (COMM_PORT + 4)


typedef struct
{
    /* data from json */
    int port;
    char *address;
    char *multicast_address;
    char *broadcast_address;
} network_config_t;


#endif  // NETWORK_H
