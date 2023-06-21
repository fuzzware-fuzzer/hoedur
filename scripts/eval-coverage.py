#!/usr/bin/env python3

import argparse
import os
import shutil

from fuzz_common import *


def main():
    parser = argparse.ArgumentParser(description='collect coverage data')
    parser.add_argument('output', help='output path (dir)')
    parser.add_argument('corpus', help='corpus path')
    parser.add_argument('--fuzzer', help='fuzzer name')
    parser.add_argument('--targets', nargs='+')
    parser.add_argument('--no-basic-block-filter', action='store_true')
    parser.add_argument('--filter-bugs', nargs='+')
    args = parser.parse_args()

    common_args = []

    # filters
    if args.no_basic_block_filter:
        common_args.append('--no-basic-block-filter')
    if args.filter_bugs:
        common_args += ['--filter-bugs'] + args.filter_bugs

    # custom targets
    common_args.append('--targets')
    common_args += args.targets

    # create output dir
    if args.fuzzer:
        name = args.fuzzer
    else:
        name = os.path.basename(args.corpus)
    charts_dir = f'{args.output}/charts'
    os.makedirs(charts_dir, exist_ok=True)

    # plots overview
    plots_file = f'{args.output}/plots.json'

    # run plot script
    plot_args = [
        '--only-coverage',
        '--root', f'{args.output}/',
        '--config_name', name,
        charts_dir,
        plots_file,
        args.corpus
    ]
    run([SCRIPTS_DIR + '/fuzz-plot-data.py'] + plot_args + common_args)

    # print plots.json file path
    eprint(plots_file)

    # create coverage summary
    run([
        SCRIPTS_DIR + '/fuzz-coverage-list.py',
        '--output', args.output,
        '--config_name', name,
        args.corpus
    ] + common_args)


if __name__ == '__main__':
    main()
