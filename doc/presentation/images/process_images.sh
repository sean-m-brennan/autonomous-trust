#!/bin/sh

for file in file spreadsheet; do
    dia -e $file.shape $file.dia
done

for file in identity reputation; do
    dia -e $file.svg $file.dia
done

for file in network; do
    dia -e $file.png $file.dia
done
