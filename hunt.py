#!/usr/bin/env python3
"""Backward compatible entry point: python3 hunt.py events.csv  ==  python3 -m irforge hunt events.csv"""
import sys

from irforge.cli import main

if __name__ == "__main__":
    sys.exit(main(["hunt"] + sys.argv[1:]))
