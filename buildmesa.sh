#! /bin/bash

cd mesa
git pull
mkdir build
cd build
meson setup --wipe
meson setup .. -D prefix="$HOME/radv-master" --libdir="$HOME/radv-master/lib" -D b_ndebug=true -D b_lto=true -D b_pgo=generate -D buildtype=release -D platforms=wayland -D gallium-drivers= -D vulkan-drivers=amd -D gles1=disabled -D gles2=disabled -D opengl=false -D strip=true
ninja -C . install
