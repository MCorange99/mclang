#!/bin/bash

echo "[cmd]: mkdir \"$HOME/.mclang\""
rm -rf "$HOME/.mclang"
mkdir -p "$HOME/.mclang"
echo "[cmd]: cd $HOME/.mclang"
pushd "$HOME/.mclang" 1> /dev/null 2> /dev/null
echo "[CMD]: git clone https://github.com/MCorange99/mcLang.git ."
git clone https://github.com/MCorange99/mcLang.git .
cp mclang.py mclang
chmod +x mclang

echo "mcLang was sucessfully installed but you still cannot use it."

echo "add '  export PATH=\"\$PATH:\$HOME/.mclang\"  ' to your .bashrc (or .zshrc if youre using zsh)"
