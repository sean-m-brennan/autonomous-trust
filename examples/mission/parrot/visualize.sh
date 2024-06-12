#!/bin/sh

firmware=anafi2
drone=anafi_ai.drone
ue_env=empty

drone_dir=/opt/parrot-sphinx/usr/share/sphinx/drones
firmware_url="https://firmware.parrot.com/Versions/${firmware}/pc/%23latest/images/${firmware}-pc.ext2.zip"
firmware_dir=${firmware}-pc.ext2.zip
firmware_loc=$firmware_dir
if [ !-e $firmware_dir ]; then
    firmware_loc=$firmware_url
fi

sphinx "${drone_dir}/${drone}"::firmware="${firmware_loc}" & parrot-ue4-$ue_env
