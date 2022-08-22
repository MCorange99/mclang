#!/bin/bash


echo "Are you sure you want to install mcLang to '~/.mclang? THis will also delete any existing installs!' (y/n): "
read b_install

if [ $b_install != "y" ]
then
    echo "Exiting!"
    exit
fi


echo "[cmd]: mkdir \"$HOME/.mclang\""
rm -rf "$HOME/.mclang"
mkdir -p "$HOME/.mclang"
echo "[cmd]: cd $HOME/.mclang"
pushd "$HOME/.mclang" 1> /dev/null 2> /dev/null

echo "Do you want to clone with ssh or https? You will need to be registered on github and also you need to have a working shh key to use ssh 
(ssh/https)?: "
read s_git_type

if [ $s_git_type = "ssh" ] 
then
    echo "[CMD]: git clone https://github.com/MCorange99/mcLang.git ."
    git clone https://github.com/MCorange99/mcLang.git .
elif [ $s_git_type = "https" ] 
then
    echo "[CMD]: git clone https://github.com/MCorange99/mcLang.git ."
    git clone https://github.com/MCorange99/mcLang.git .
else
    echo "Unknown Type $s_git_type."
    exit
fi
rm -r "$HOME/.mclang/*"
cp mclang.py mclang
chmod +x mclang

echo "mcLang was sucessfully installed but you still cannot use it."

echo "add '  export PATH=\"\$PATH:\$HOME/.mclang\"  ' to your .bashrc (or .zshrc if youre using zsh)"