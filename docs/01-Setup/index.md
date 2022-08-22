# Setting up

An introduction to stack based concatinative programming

## Windows

You will need to enable `Windows subsystem for linux` feature in `Additional Features`.
Then install ubuntu 20 (You can use Ubuntu 22 but 20 has better support).
After that follow the instructions for Linux.

## Linux && MacOS

You will need nasm and python3 if you dont ahve them already by:

Ubuntu:

```sh
sudo apt update
sudo apt upgrade
sudo apt install nasm python3
```

Archlinux:

```sh
sudo pacman -Syu nasm python3
```

## Installing mclang

To download and run the installer run this:

```sh
curl https://raw.githubusercontent.com/MCorange99/mcLang/main/install.sh -o /tmp/install.sh ; bash /tmp/install.sh
```

Then it will ask you to put `export PATH="$PATH:$HOME/.mclang"` into your .bashrc or .zshrc

You can do that by doing:

```sh
echo "export PATH=\"$PATH:$HOME/.mclang\"" >> ~/.bashrc
```

Now if you reload your shell (Or you can do `source ~/.bashrc`)

You can now use `mclang` compiler.
