#!/bin/sh

if [ $# -eq 0 ]
then
    echo "Usage: send.sh <docker id>"
else
    sudo docker cp ./fs/exp $1:/solve
fi