#!/usr/bin/env python
import json
import sys
import argparse
import re
import time
import os
from datetime import datetime

win_multiline_date_rex = re.compile("^\d+/\d+/\d+ \d+:\d+:\d+ (AM|PM)$")

def inject_win_multiline(args):
    computer_name_rex = re.compile("^ComputerName=(.*)$")
    record_number_rex = re.compile("RecordNumber=\d+\n", re.MULTILINE)
    record_number = 0
    inject = args.inject
    input = args.input
    first_time = sys.maxsize

    for l in filter(lambda x: win_multiline_date_rex.match(x) is not None, iter(lambda: inject.readline(), '')):
        tt = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
        first_time = min(tt, first_time)
    inject.seek(0, 0)

    def read_win_multiline_event(fh, _map=False):
        evt_buff = ""
        evt_time = 0
        rec = False
        cur_pos = fh.tell()
        ended = False
        while True:
            l = fh.readline()
            if not l:
                ended = True
                break
            if win_multiline_date_rex.match(l) and not rec:
                rec = True
                evt_time = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
            elif win_multiline_date_rex.match(l):
                fh.seek(cur_pos)
                break
            if rec:
                if _map:
                    if win_multiline_date_rex.match(l):
                        evt_time = (evt_time - first_time) + args.timestamp
                        l = "%s\n" % datetime.fromtimestamp(evt_time).strftime("%m/%d/%Y %H:%M:%S %p")
                evt_buff += l
            cur_pos = fh.tell()
        return evt_time, evt_buff, ended

    def write_evt(evt, record_number):
        evt = re.sub("RecordNumber=\d+", "RecordNumber=%d" % record_number, evt, 1)
        args.output.write(evt)
        return record_number + 1

    read_input = True
    read_inject = True
    ended_input = False
    ended_inject = False
    while not ended_input or not ended_inject:
        if read_input:
            cur_input_t, cur_input_evt, ended_input = read_win_multiline_event(input)
            read_input = False
        if read_inject:
            cur_inject_t, cur_inject_evt, ended_inject = read_win_multiline_event(inject, True)
            read_inject = False

        if cur_input_t < cur_inject_t:
            record_number = write_evt(cur_input_evt, record_number)
            cur_input_t = sys.maxsize
            read_input = not ended_input
        else:
            record_number = write_evt(cur_inject_evt, record_number)
            cur_inject_t = sys.maxsize
            read_inject = not ended_inject


def read_win_multiline_event(fh):
    evt_buff = ""
    evt_time = 0
    rec = False
    for l in fh:
        if win_multiline_date_rex.match(l) and not rec:
            rec = True
            evt_time = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
        elif win_multiline_date_rex.match(l):
            break
        if rec:
            evt_buff += "\n%s" % l
        return evt_time, evt_buff

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--format", help="input file format", choices=["win-multiline"], default="win-multiline")
parser.add_argument("-t", "--timestamp", help="base timestamp", required=True, type=int)
parser.add_argument("-d", "--domain-map", help="json dictionary with domains to map", type=json.loads)
parser.add_argument("-m", "--machine-map", help="json dictionary with machines to map", type=json.loads)
parser.add_argument("inject", type=argparse.FileType('r'))
parser.add_argument("input", type=argparse.FileType('r'))
parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=sys.stdout)

if __name__ == "__main__":
    args = parser.parse_args()

    if args.format == "win-multiline":
        inject_win_multiline(args)
