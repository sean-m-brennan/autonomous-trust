#!/bin/bash

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