#! /bin/bash

cd mesa
git pull
mkdir build
cd build
export CFLAGS="-march=native -O3 -pipe -fgraphite-identity -floop-strip-mine -floop-nest-optimize -fno-semantic-interposition -fipa-pta -flto -fdevirtualize-at-ltrans -flto-partition=one"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="-Wl,-O1,--sort-common,--as-needed,-z,now ${CFLAGS}"
meson setup --wipe
meson setup .. -D prefix="$HOME/radv-master" --libdir="$HOME/radv-master/lib" -D b_ndebug=true -D b_lto=true -D b_pgo=generate -D buildtype=release -D platforms=x11,wayland -D gallium-drivers= -D vulkan-drivers=amd -D gles1=disabled -D gles2=disabled -D opengl=false -D strip=true
ninja -C . install
