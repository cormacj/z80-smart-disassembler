#!/usr/bin/env bash

if [ "$1" == "" ]; then
  echo -e "Usage: $0 filename hex_load_location\n"
  echo -e "Example: $0 CPMFILE.COM 0x100 >cpmfile.txt\n"
  #echo "Please supply a filename and the loading memory address, eg RODOS213.ROM 0xc000"
  echo "This is used to generate a template for decoding strings in the file."
  echo "Note, you'll have to do some manual cleanup on the output."
  exit 1
fi
if [ "$2" == "" ]; then
  echo "Please supply memory location for the code."
  echo "Usually these are:"
  echo "    ROMS: 0xc000"
  echo "    CP/M programs (.COM files): 0x100"
  echo "Regular Amstrad binaries can be anywhere so you'll have to use something like '|INFO,filename' from RODOS to see where it loads"
  exit 1
fi

#Convert hex to decimal
export memloc=$(printf "%d\n" $2)

#Now produce a template file
#Example output:
#0xa45,0xa4f,s,S_a45
strings -td  $1 |awk -dvars.txt -v o="$memloc" '{offs=o;strdata=substr($0,9,9999); strlen=length(strdata); printf(";----\n;db \"%s\"\n0x%x,0x%x,s,S_%x\n",substr($0,9,9999),$1+offs,$1+offs+strlen,$1+offs)}'
