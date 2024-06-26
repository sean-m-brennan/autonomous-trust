#!/bin/sh

grep -r "define E" autonomous_trust | grep -v "define EXCEPTION" | grep -v "define ERROR" | awk '{print $3 "  " $2}' | grep '[0-9]' | sort
