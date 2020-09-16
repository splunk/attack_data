#!/usr/bin/env python
import json
import sys
import argparse
import re
import time
from datetime import datetime


def inject_win_multiline(args):
    date_rex = re.compile("^\d+/\d+/\d+ \d+:\d+:\d+ (AM|PM)$")
    first_time = 0
    with args.input as fh:
        first_time = sys.maxsize
        for l in filter(lambda x: date_rex.match(x) is not None, iter(lambda: fh.readline(), '')):
            tt = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
            first_time = min(tt, first_time)
        fh.seek(0, 0)

        for l in fh:
            if date_rex.match(l):
                t = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
                new_time = datetime.fromtimestamp((t - first_time) + args.timestamp).strftime("%m/%d/%Y %H:%M:%S %p")
                args.output.write("%s\n" % new_time)
            else:
                args.output.write(l)


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--format", help="input file format", choices=["win-multiline"], default="win-multiline")
parser.add_argument("-t", "--timestamp", help="base timestamp", required=True, type=int)
parser.add_argument("-d", "--domain-map", help="json dictionary with domains to map", type=json.loads)
parser.add_argument("-m", "--machine-map", help="json dictionary with machines to map", type=json.loads)
parser.add_argument("input", type=argparse.FileType('r'))
parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=sys.stdout)

if __name__ == "__main__":
    args = parser.parse_args()

    if args.format == "win-multiline":
        inject_win_multiline(args)
