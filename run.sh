#!/usr/bin/env bash

set -eu

SRC_DIR="src"
BUILD_DIR=".build"

echo "-----> [1/4] Cleaning build environment..."
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
echo '*' > $BUILD_DIR/.gitignore
if [[ $(pgrep challenger) ]]; then
    pkill challenger
fi

echo "-----> [2/4] Compiling C Challenger..."
cc "$SRC_DIR/challenger.c" "$SRC_DIR/mongoose.c" \
    -o "$BUILD_DIR/challenger" \
    -I "$SRC_DIR" -Wall -lssl -lcrypto

echo "-----> [3/4] Compiling Erlang files..."
erlc -o $BUILD_DIR "$SRC_DIR/"*.erl

echo "-----> [4/4] Copying static assets..."
cp "$SRC_DIR/index.html" $BUILD_DIR

echo "============================================"
echo "Build complete. Artifacts are in $BUILD_DIR/"
echo "Starting Load Balancer..."
echo "Access via http://localhost:8080"
echo "============================================"

# Change directory to build so that:
# 1. The beam files are in the current path (.)
# 2. 'index.html' is found by server.erl
# 3. './challenger' is found by load_balancer.erl
# 4. 'pastebin.db' is created inside .build/
cd $BUILD_DIR

# Run Erlang
# -noshell: Don't open the interactive shell
# -pa .: Add current directory to code path
# -s load_balancer start: Run load_balancer:start()
erl -noshell -pa . -s load_balancer start
