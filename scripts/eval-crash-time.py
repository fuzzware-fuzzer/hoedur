#!/usr/bin/env python3

import argparse
import glob
import json
import os
import threading
import yaml

from fuzz_common import *


def main():
    parser = argparse.ArgumentParser(description='collect crash times')
    parser.add_argument('corpus')
    parser.add_argument('--output-json', type=str)
    parser.add_argument('--include-non-crashing-inputs', action='store_true')
    parser.add_argument('--exclude-unknown-crashes', action='store_true')
    parser.add_argument('--targets', nargs='+')
    parser.add_argument('--cores', type=int, default=cpu_cores(logical=True))
    args = parser.parse_args()

    # build
    build('hoedur-eval-crash')

    threads = []
    timings = {}
    targets = list(args.targets)
    max = len(args.targets)

    # start threads
    for _ in range(args.cores):
        t = threading.Thread(target=crash_time, args=(
            args.corpus, args.include_non_crashing_inputs, args.exclude_unknown_crashes, timings, targets, max))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # DEBUG: eprint(timings)

    # collect timings
    experiment_timings = {}
    for (target, target_timing) in timings.items():
        # collect target bugs
        bugs = []
        for report_timings in target_timing:
            bugs += list(report_timings.keys())

        # dedup + sort bugs
        bugs = sorted(list(set(bugs)))

        # create target
        if not target in experiment_timings:
            experiment_timings[target] = {}

        # collect bug timings
        for bug in bugs:
            # create bug
            experiment_timings[target][bug] = []

            # collect timings
            for report_timings in target_timing:
                if bug in report_timings:
                    time = report_timings[bug]['time']
                else:
                    time = None

                experiment_timings[target][bug].append(time)

    # write output txt
    for (target, bug_timings) in experiment_timings.items():
        # print bug timings
        for (bug, timings) in bug_timings.items():

            # target + bug
            print(target, bug, end='')

            # timings
            for time in timings:
                if time:
                    print('', time, end='')
                else:
                    print('', '-', end='')

            # endline
            print('')

    # write output json
    if args.output_json:
        open(args.output_json, 'w').write(
            json.dumps(experiment_timings, indent=4)
        )


def crash_time(corpus, include_non_crashing_inputs, exclude_unknown_crashes, timings, targets, max):
    # include non-crashing inputs (for bug hooks) in timings
    args = []
    if include_non_crashing_inputs:
        args = ['--include-non-crashing-inputs']

    while len(targets) > 0:
        # next target
        target = targets.pop(0)
        eprint('run', max - len(targets), '/', max, ':', target)

        # collect reports
        reports = glob.glob(
            '{}/TARGET-{}-*.report.bin.zst'.format(corpus, target.replace('/', '-')))
        reports.sort()

        target_timing = []
        for report in reports:
            # collect crash timings in report group
            result = subprocess.run(
                binary('hoedur-eval-crash') + ['--yaml'] + args + [report], capture_output=True)

            # parse crash timings
            crash_timings = yaml.safe_load(result.stdout)
            # DEBUG: eprint(crash_timings)

            # select first / matching bug
            report_timing = {}
            for [reason, crash_time] in crash_timings:
                # crash eval data
                time = crash_time['time']
                source = crash_time['source']

                # bug / crash reason
                if 'Bug' in reason:
                    bug = reason['Bug']
                elif not exclude_unknown_crashes:
                    if 'Crash' in reason:
                        crash = reason['Crash']
                        bug = 'crash_pc-{:08x}_ra-{:08x}'.format(
                            crash['pc'], crash['ra'])
                    elif 'NonExecutable' in reason:
                        non_exec = reason['NonExecutable']
                        bug = 'non-exec_pc-{:08x}'.format(non_exec['pc'])
                    elif 'RomWrite' in reason:
                        rom_write = reason['RomWrite']
                        bug = 'rom-write_pc-{:08x}_addr-{:08x}'.format(
                            rom_write['pc'], rom_write['addr'])
                    else:
                        assert (False)
                else:
                    continue

                report_timing[bug] = {'time': time, 'source': source}

            # collect report timings
            target_timing.append(report_timing)

        # collect target timings
        timings[target] = target_timing

        eprint('done', target)


if __name__ == '__main__':
    main()
