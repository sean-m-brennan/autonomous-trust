#!/bin/sh
# ******************
#  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

firmware=anafi2
drone=anafi_ai.drone
ue_env=empty

drone_dir=/opt/parrot-sphinx/usr/share/sphinx/drones
firmware_url="https://firmware.parrot.com/Versions/${firmware}/pc/%23latest/images/${firmware}-pc.ext2.zip"
firmware_dir=${firmware}-pc.ext2.zip
firmware_loc=$firmware_dir
if [ ! -e $firmware_dir ]; then
    firmware_loc=$firmware_url
fi

sphinx "${drone_dir}/${drone}"::firmware="${firmware_loc}" & parrot-ue4-$ue_env
