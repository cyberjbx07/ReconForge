"""
Module: Input Handler
Description: Gets and cleans user input
Author: CyberJBX
"""
import re

def get_target():
    target = input("Enter target (IP/Domain): ").strip()

    # ==========================
    # REMOVE PROTOCOL
    # ==========================
    if target.startswith("http://"):
        target = target[len("http://"):]
    elif target.startswith("https://"):
        target = target[len("https://"):]

    # ==========================
    # REMOVE WWW
    # ==========================
    if target.startswith("www."):
        target = target[len("www."):]

    # ==========================
    # REMOVE TRAILING SLASHES
    # ==========================
    target = target.strip("/")

    # ==========================
    # REMOVE BACKSLASHES ❗
    # ==========================
    target = target.replace("\\", "")

    # ==========================
    # FINAL CLEAN
    # ==========================
    target = re.sub(r"[^a-zA-Z0-9.-]", "", target)

    return target