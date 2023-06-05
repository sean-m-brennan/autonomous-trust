#!/bin/sh

cd fs0 && find . | cpio -o --format=newc | gzip -9 >../initramfz