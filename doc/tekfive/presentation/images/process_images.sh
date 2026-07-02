#!/bin/bash
# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

this_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

cd "$this_dir" || exit
for file in file spreadsheet demon devil neutral police smiley upset spy; do
    dia -e $file.shape $file.dia
    rm -f $file.png
done

for file in language negotiation identity reputation optimization prioritization; do
    dia -e $file.svg $file.dia
done

for file in network; do
    dia -e $file.png $file.dia
done

for file in optimization prioritization; do
    cp $file.svg $file.svg.tmp
    cat $file.svg.tmp | head -n 2 > $file.svg
    echo "<?xml-stylesheet type=\"text/css\" href=\"../css/$file.css\"?>" >> $file.svg
    cat $file.svg.tmp | tail -n +3 >> $file.svg
    rm -f $file.svg.tmp
done