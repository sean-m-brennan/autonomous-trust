#!/bin/bash

this_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

cd "$this_dir" || exit
for file in file spreadsheet demon devil neutral police smiley upset; do
    dia -e $file.shape $file.dia
done

for file in language negotiation identity reputation optimization; do
    dia -e $file.svg $file.dia
done

for file in network; do
    dia -e $file.png $file.dia
done

cp optimization.svg optimization.svg.tmp
cat optimization.svg.tmp | head -n 2 > optimization.svg
echo '<?xml-stylesheet type="text/css" href="../css/optimization.css"?>' >> optimization.svg
cat optimization.svg.tmp | tail -n +3 >> optimization.svg
rm -f optimization.svg.tmp
