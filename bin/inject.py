#!/usr/bin/env python3
import json
import sys
import argparse
import re
import time
from datetime import datetime

win_multiline_date_rex = re.compile(r"^\d+/\d+/\d+ \d+:\d+:\d+ (AM|PM)$")
machine_parse_rex = re.compile(r"(.*)\.([^\.]+)\.[^\.]+$")


def inject_win_multiline(args):
    """
    Handling injection of windows multi-line logs as exported from Splunk.
    This script assumes that logs are sorted by time at the time they were exported.
    :param args:
    :return: injects into input dataset the events and writes them to a single log
    """
    log_field = re.compile(r"^[\t\s]+([^:]+):[\t\s]+(.*)")
    computer_name_rex = re.compile("^ComputerName=.*")
    map_fields = ["Account Name", "Account Domain", "Security ID", "Workstation Name"]
    record_number = 0
    inject = args.inject
    input = args.input
    first_time = sys.maxsize

    # Populate replacement functions based on machine mappings
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

    # Find the earliest time in the inject logs to perform time mapping
    if args.timestamp is not None:
        for l in filter(lambda x: win_multiline_date_rex.match(x) is not None, iter(lambda: inject.readline(), '')):
            tt = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
            first_time = min(tt, first_time)
        inject.seek(0, 0)

    def read_win_multiline_event(fh, _map=False):
        """
        Reads next window event in the file handler.
        Performs the mapping for inject's logs
        :param fh: log filehandler
        :param _map: True if we want to apply field mapping
        :return: a windows security event, time of the event, and whether this was the last event in the log
        """
        evt_buff = ""
        evt_time = 0
        rec = False
        cur_pos = fh.tell()
        ended = False
        while True:
            l = fh.readline()
            if not l:
                # Last event
                ended = True
                break
            if win_multiline_date_rex.match(l) and not rec:
                rec = True
                evt_time = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
            elif win_multiline_date_rex.match(l):
                # This timestamp belongs to next event.
                # Move the file handler cursor to its head.
                fh.seek(cur_pos)
                break
            if rec:
                if _map:
                    # Perform field mapping
                    if win_multiline_date_rex.match(l) and args.timestamp is not None:
                        evt_time = (evt_time - first_time) + args.timestamp
                        l = "%s\n" % datetime.fromtimestamp(evt_time).strftime("%m/%d/%Y %H:%M:%S %p")
                    elif computer_name_rex.match(l):
                        for r in replace_func:
                            l = r(l)
                    else:
                        m = log_field.match(l)
                        if m:
                            field = m.group(1)
                            if field in map_fields:
                                for r in replace_func:
                                    l = r(l)
                evt_buff += l
            cur_pos = fh.tell()
        return evt_time, evt_buff, ended

    def write_evt(evt, rn):
        # Write event updating RecordNumber
        evt = re.sub(r"RecordNumber=\d+", "RecordNumber=%d" % rn, evt, 1)
        args.output.write(evt)
        return rn + 1

    read_input = True
    read_inject = True
    ended_input = False
    ended_inject = False
    while not ended_input or not ended_inject:
        # Read at most one event from each log (input, inject)
        if read_input:
            cur_input_t, cur_input_evt, ended_input = read_win_multiline_event(input)
            read_input = False
        if read_inject:
            cur_inject_t, cur_inject_evt, ended_inject = read_win_multiline_event(inject, True)
            read_inject = False

        # Write events out keeping them ordered.
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
parser.add_argument("-t", "--timestamp", help="base timestamp", required=False, type=int)
parser.add_argument("-m", "--machine-map", help="json dictionary with machines to map", type=json.loads)
parser.add_argument("inject", type=argparse.FileType('r'))
parser.add_argument("input", type=argparse.FileType('r'))
parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=sys.stdout)

if __name__ == "__main__":
    args = parser.parse_args()

    if args.format == "win-multiline":
        inject_win_multiline(args)
