#!/usr/bin/env bash

set -e

source scripts/install_node.sh $1
cd tools/nodejs
make clean
./configure

npm install --build-from-source
npm test
export PATH=$(npm bin):$PATH
node-pre-gyp package testpackage testbinary
node-pre-gyp publish
node-pre-gyp info