import subprocess as sp
from os import path

def is_installed(cmd):
    c = sp.call([cmd, "--version"])

    if c == 0:
        return True
    else:
        return False



file_list_url = "https://raw.githubusercontent.com/MCorange99/mcLang/main/install_files.txt"

sp.call(["curl", file_list_url, "-o", "./install_files.txt"])

def call_cmd_echoed(cmd):
    print("[CMD]: " + " ".join(cmd))
    exit_code = sp.call(cmd)
    if exit_code == 0:
        print("[INFO]: OK")
    else:
        print("[ERR]: Command '%s' failed with exit code %d" % (" ".join(cmd), exit_code))
        exit(1)



files = [
    # ("mclang.py", "https://raw.githubusercontent.com/MCorange99/mcLang/main/mclang.py"),
    # ("include/std.mcl", "https://raw.githubusercontent.com/MCorange99/mcLang/main/include/std.mcl")
    # ("include/linux.mcl", "https://raw.githubusercontent.com/MCorange99/mcLang/main/include/linux.mcl")
]
with open("./install_files.txt") as f:
    lines = f.readlines()

    for line in lines:
        line = line.split("#")[0]
        fn = line.split("|")[0]
        url = line.split("|")[1]
        files.append()



host_os = input("What is your os(windows, linux, macos): ")

bin_path = input("What is your bin path (Do not use '/bin','/usr/bin','C:\\windows', use a custom path ex. '/home/jeff/.bin/' or 'C:\\Users\\jeff\\.bin\\')\n>")

for file in files:
    call_cmd_echoed(["curl", file[1], "-o", path.join(bin_path, file[0])])




if host_os == "windows": 
    print("It is recommended that you use ubuntu with wsl2. Install instructions here: https://docs.microsoft.com/en-us/windows/wsl/install")
is_installed("python")