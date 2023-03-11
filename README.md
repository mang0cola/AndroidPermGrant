# AndroidPermGrant

android permission operation with frida

## usage

usage: main.py [-h] (-g | -r | -l) [-p PERM] -u UID

Grant/Revoke permission to target uid with frida

options:

  -h, --help            show this help message and exit

  -g, --grant           grant permission to target uid

  -r, --revoke          revoke permission from target uid

  -l, --list            list permissions of target uid

  -p PERM, --perm PERM  target permission name

  -u UID, --uid UID     target uid