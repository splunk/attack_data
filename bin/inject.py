#!/usr/bin/env python
import json
import sys
import argparse
import re
import time
from datetime import datetime

win_multiline_date_rex = re.compile(r"^\d+/\d+/\d+ \d+:\d+:\d+ (AM|PM)$")
machine_parse_rex = re.compile(r"(.*)\.([^\.]+)\.[^\.]+$")


def inject_win_multiline(args):
    log_field = re.compile(r"^[\t\s]+([^:]+):[\t\s]+(.*)")
    record_number = 0
    inject = args.inject
    input = args.input
    first_time = sys.maxsize

    replace_func = []
    for m in args.machine_map.keys():
        old_machine = machine_parse_rex.match(m)
        new_machine = machine_parse_rex.match(args.machine_map[m])
        if old_machine and new_machine:
            maps = list(zip(old_machine.groups(), new_machine.groups()))
            replace_func.append(lambda l: re.sub(old_machine.group(0), new_machine.group(0), l))
            simple_sub = list(map(lambda t: lambda l: re.sub(t[0], t[1], l), maps))
            upper_sub = list(map(lambda t: lambda l: re.sub(t[0].upper(), t[1].upper(), l), maps))
            lower_sub = list(map(lambda t: lambda l: re.sub(t[0].lower(), t[1].lower(), l), maps))

            replace_func.extend(simple_sub)
            replace_func.extend(upper_sub)
            replace_func.extend(lower_sub)

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
                    else:
                        if log_field.match(l):
                            for r in replace_func:
                                l = r(l)
                evt_buff += l
            cur_pos = fh.tell()
        return evt_time, evt_buff, ended

    def write_evt(evt, rn):
        evt = re.sub(r"RecordNumber=\d+", "RecordNumber=%d" % rn, evt, 1)
        args.output.write(evt)
        return rn + 1

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
