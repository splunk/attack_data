#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
from file_read_backwards import FileReadBackwards
from datetime import datetime

win_multiline_date_rex = re.compile(r"^\d+/\d+/\d+ \d+:\d+:\d+ (AM|PM)$")
machine_parse_rex = re.compile(r"(.*)\.([^\.]+)\.[^\.]+$")


class LogReader:

    def __init__(self, fh, rev, head_rex, evt_mapper=lambda x: x):
        self.fh = fh
        self.reversed = rev
        self.evt_buffer = ""
        self.head_rex = re.compile(head_rex)
        self.evt_mapper = evt_mapper
        self._ended = False

    def read_event(self):
        evt_buff = self.evt_buffer
        while True:
            l = self.fh.readline()
            self.evt_buffer = l
            if l:
                if self.head_rex.match(l) and len(evt_buff) > 0:
                    if self.reversed:
                        self.evt_buffer = self.fh.readline()
                        if not self.evt_buffer:
                            self._ended = True
                        return l + evt_buff
                    else:
                        return self.evt_mapper(evt_buff)
                if self.reversed:
                    evt_buff = l + evt_buff
                else:
                    evt_buff = evt_buff + l
            else:
                self._ended = True
                return self.evt_mapper(evt_buff)

    def ended(self):
        return self._ended


def inject_win_multiline(args):
    """
    Handling injection of windows multi-line logs as exported from Splunk.
    This script assumes that logs are sorted by time at the time they were exported.
    :param args:
    :return: injects into input dataset the events and writes them to a single log
    """
    log_field = re.compile(r"^[\t\s]+([^:]+):[\t\s]+(.*)")
    computer_name_rex = re.compile("^ComputerName=.*")
    map_fields = ["Account Name", "Account Domain", "Security ID", "Workstation Name", "Supplied Realm Name",
                  "Service ID", "User ID", "Group Domain"]
    record_number = 0
    inject = args.inject if not args.reverse_inject else FileReadBackwards(args.inject.name)
    input = args.input if not args.reverse_input else FileReadBackwards(args.input.name)
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

    def write_evt(evt, rn):
        # Write event updating RecordNumber
        evt = re.sub(r"RecordNumber=\d+", "RecordNumber=%d" % rn, evt, 1)
        args.output.write(evt)
        return rn + 1

    def extract_time(evt):
        m = re.match(r"(^\d+/\d+/\d+ \d+:\d+:\d+ (AM|PM))\n.*", evt, re.MULTILINE)
        if m:
            t_str = m.group(1)
            return time.mktime(time.strptime(t_str, "%m/%d/%Y %H:%M:%S %p"))

    def event_mapping(evt):
        mapped = []
        for l in evt.split("\n"):
            if win_multiline_date_rex.match(l) and args.timestamp is not None:
                evt_time = time.mktime(time.strptime(l.strip(), "%m/%d/%Y %H:%M:%S %p"))
                evt_time = (evt_time - first_time) + args.timestamp
                l = "%s\n" % datetime.fromtimestamp(evt_time).strftime("%m/%d/%Y %H:%M:%S %p")
            elif computer_name_rex.match(l):
                for r in replace_func:
                    l = r(l)
            m = log_field.match(l)
            if m:
                field = m.group(1)
                if field in map_fields:
                    for r in replace_func:
                        l = r(l)
            mapped.append(l)
        return "\n".join(mapped)

    read_input = True
    read_inject = True
    inject_reader = LogReader(inject, args.reverse_inject, win_multiline_date_rex, event_mapping)
    input_reader = LogReader(input, args.reverse_input, win_multiline_date_rex)
    cur_input_t =sys.maxsize
    cur_inject_t = sys.maxsize
    while not inject_reader.ended() or not input_reader.ended():
        if read_input and not input_reader.ended():
            cur_input_evt = input_reader.read_event()
            cur_input_t = extract_time(cur_input_evt)
            read_input = False
        if read_inject and not inject_reader.ended():
            cur_inject_evt = inject_reader.read_event()
            cur_inject_t = extract_time(cur_inject_evt)
            read_inject = False

        # Write events out keeping them ordered.
        if cur_input_t < cur_inject_t:
            record_number = write_evt(cur_input_evt, record_number)
            cur_input_t = sys.maxsize
            read_input = not input_reader.ended()
        else:
            record_number = write_evt(cur_inject_evt, record_number)
            cur_inject_t = sys.maxsize
            read_inject = not inject_reader.ended()


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--format", help="input file format", choices=["win-multiline"], default="win-multiline")
parser.add_argument("-t", "--timestamp", help="base timestamp", required=False, type=int)
parser.add_argument("-m", "--machine-map", help="json dictionary with machines to map", type=json.loads)
parser.add_argument("--reverse-inject", action='store_true')
parser.add_argument("--reverse-input", action='store_true')
parser.add_argument("inject", type=argparse.FileType('r'))
parser.add_argument("input", type=argparse.FileType('r'))
parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=sys.stdout)

if __name__ == "__main__":
    args = parser.parse_args()

    if args.format == "win-multiline":
        inject_win_multiline(args)
