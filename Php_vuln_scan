#!/usr/bin/env python3

'''
author : Den Miles | @datkidden

Description : To find unsafe functions on any
php script and give you information about it. Download the file locally and compare

Requiremnets : termcolor, tabulate
'''

import os
import sys
import time
import re
from termcolor import cprint
from tabulate import tabulate

if len(sys.argv) != 3:
    cprint(f"[+] Usage : ./{sys.argv[0]} path extension", "red")
    cprint(f"[+] Example : ./{sys.argv[0]} /var/www/plugin php", "red")
    sys.exit(0)

path = sys.argv[1]
extension = sys.argv[2]
final_files = []
reg = r'\((.*)\);'
unsafe = ["system", "shell_exec", "exec", "passthru", "eval"]


def spider(script_path):
    if not os.path.exists(script_path):
        cprint("[-] Directory does not exist", "red")
        sys.exit(0)
    cprint("[+] Scanning started for the script ..", "green")
    for root, _, files in os.walk(script_path, topdown=False):
        for fi in files:
            dfile = os.path.join(root, fi)
            if dfile.endswith(f".{extension}"):
                final_files.append(dfile)
    cprint(f"[+] {len(final_files)} {extension} files found", "green")


def scanner(files_list):
    results = []
    for fi in files_list:
        with open(fi, "r") as f:
            data = f.readlines()
            for linen, line in enumerate(data, start=1):
                line_no = line.strip("\n")
                for unsafe_function in unsafe:
                    final_reg = unsafe_function + reg
                    try:
                        if re.search(final_reg, line_no):
                            file_result = [fi, unsafe_function, linen]
                            results.append(file_result)
                    except re.error as e:
                        cprint(f"Regex error: {e}", "red")
    if results:
        print(tabulate(results,
                       headers=['File Name', 'Function Name', "Line Number"],
                       tablefmt='psql', numalign="center", stralign="center"))
    else:
        cprint("[+] No unsafe functions found!", "green")


spider(path)
scanner(final_files)
