#!/usr/bin/env python3

import argparse
import glob
import os
import threading
from pathlib import Path

from fuzz_common import *


def main():
    parser = argparse.ArgumentParser(description='create coverage list')
    parser.add_argument('corpus', help='corpus path')
    parser.add_argument('--output')
    parser.add_argument('--config_name')
    parser.add_argument('--targets', nargs='+')
    parser.add_argument('--no-basic-block-filter', action='store_true')
    parser.add_argument('--filter-bugs', nargs='+', default=[])
    args = parser.parse_args()

    # corpus
    corpus = Path(os.path.normpath(args.corpus))

    # filter bugs
    bug_filter = []
    for bug in args.filter_bugs:
        bug_filter += ['--filter-bug', bug]

    # output dir
    if args.output:
        output = Path(args.output)

        # config name
        if args.config_name:
            config_name = args.config_name
        else:
            config_name = os.path.basename(corpus)
    else:
        output = Path(corpus) / '_bb'
        config_name = None

    # collect reports
    runs = []
    for target in args.targets:
        target_filename = target.replace('/', '-')
        for report in glob.glob('{}/TARGET-{}-*.report.bin.zst'.format(corpus, target_filename)):
            runs.append((corpus, report, target, target_filename))
    max = len(runs)

    # build
    build('hoedur-coverage-list')

    # start thread per core of host
    threads = []
    for num in range(cpu_cores()):
        t = threading.Thread(target=run_coverage_list, args=(
            runs, args.no_basic_block_filter, output, config_name, bug_filter, max))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


def run_coverage_list(runs, no_basic_block_filter, output, config_name, bug_filter, max):
    while len(runs) > 0:
        (corpus, report, target, target_filename) = runs.pop(0)

        eprint('run', max - len(runs), '/', max, ':', corpus, target_filename)

        basename = os.path.basename(report).replace('.report.bin.zst', '')

        # optional basic block filter
        if no_basic_block_filter:
            bb_filter = []
        else:
            bb_filter = [
                '--valid-basic-blocks',
                f'{HOEDUR_TARGETS}/arm/{target}/valid_basic_blocks.txt',
            ]

        # output dirs
        output_details = output / 'details'
        output_superset = output / 'summary'

        # append config_name if set
        if config_name:
            output_details /= config_name
            output_superset /= config_name

        # mkdir
        os.makedirs(output_details, exist_ok=True)
        os.makedirs(output_superset, exist_ok=True)

        run(binary('hoedur-coverage-list') + [
            '--output-superset', output_superset / f'{basename}.txt',
            '--output', output_details / f'{basename}.coverage.tar.zst',
        ] + bb_filter + bug_filter + [
            report
        ])


if __name__ == '__main__':
    main()
