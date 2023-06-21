#!/usr/bin/env python3

import argparse
import glob
import os
import threading

from fuzz_common import *


def main():
    parser = argparse.ArgumentParser(description='merge runs into group')
    parser.add_argument('corpus')
    parser.add_argument('--output-dir')
    parser.add_argument('--group', type=int, default=4)
    parser.add_argument('--targets', nargs='+')
    parser.add_argument('--cores', type=int, default=cpu_cores(logical=True))
    args = parser.parse_args()

    # make ouput dir
    os.makedirs(args.output_dir, exist_ok=True)

    # build
    build('hoedur-merge-report')

    threads = []
    targets = list(args.targets)
    max = len(args.targets)

    # start threads
    for _ in range(args.cores):
        t = threading.Thread(target=merge_report, args=(
            args.corpus, args.group, args.output_dir, targets, max))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


def merge_report(corpus, group_size, output_dir, targets, max):
    while len(targets) > 0:
        # next
        target = targets.pop(0)
        eprint('run', max - len(targets), '/', max, ':', target)

        # collect reports
        reports = glob.glob(
            '{}/TARGET-{}-*.report.bin.zst'.format(corpus, target.replace('/', '-')))
        reports.sort()

        # verify count
        remainder = len(reports) % group_size
        if remainder != 0:
            eprint(f'WARN len(reports) % {group_size} == {remainder}')

        # group reports
        group_count = len(reports) // group_size
        for i in range(group_count):
            name = 'TARGET-{}-RUN-{:02d}'.format(target.replace('/', '-'), i+1)
            output = '{}/{}.report.bin.zst'.format(output_dir, name)
            report_group = reports[(i * group_size): ((i+1) * group_size)]

            # merge reports
            subprocess.run(binary('hoedur-merge-report') + [
                '--name',
                name,
                '--output',
                output
            ] + report_group)

        eprint('done', target)


if __name__ == '__main__':
    main()
