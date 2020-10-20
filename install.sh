#!/bin/bash

sudo apt install python3 python3-tabulate

sudo cp p4-traffictool /usr/bin/

sudo mkdir -p /usr/share/p4-traffictool/src
sudo mkdir -p /usr/share/p4-traffictool/templates
sudo cp src/*.py /usr/share/p4-traffictool/src/
sudo cp templates/* /usr/share/p4-traffictool/templates/