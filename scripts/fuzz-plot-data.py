#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path
import threading

from fuzz_common import *


def merge_dict(dst, src):
    for key in src.keys():
        if isinstance(src[key], dict) and (key in dst and isinstance(dst[key], dict)):
            # recursive merge
            merge_dict(dst[key], src[key])
        else:
            dst[key] = src[key]


def main():
    parser = argparse.ArgumentParser(description='create plot data')
    parser.add_argument('output', help='output path (dir)')
    parser.add_argument('plot', help='plot overview (json)')
    parser.add_argument('corpus', help='corpus path')
    parser.add_argument('--config_name')
    parser.add_argument('--targets', nargs='+')
    parser.add_argument('--root')
    parser.add_argument('--no-basic-block-filter', action='store_true')
    parser.add_argument('--only-coverage', action='store_true')
    parser.add_argument('--filter-bugs', nargs='+', default=[])
    args = parser.parse_args()

    # optional bug filter
    bug_filter = []
    for bug in args.filter_bugs:
        bug_filter += ['--filter-bug', bug]

    # build
    build('hoedur-plot-data')

    # read plot overview
    plot = {'data': {}, 'plots': {}}
    if os.path.isfile(args.plot):
        old = json.loads(open(args.plot).read())

        if 'data' in old:
            plot['data'] = old['data']

    # normalize path (e.g. ignore empty dir '/a//b')
    corpus = Path(os.path.normpath(args.corpus))

    # config name
    if args.config_name:
        config_name = args.config_name
    else:
        config_name = corpus.name

    # paths
    output = Path(args.output)
    root = args.root and Path(args.root)

    # runs
    runs = []
    for target in args.targets:
        target_filename = target.replace('/', '-')
        for report in corpus.glob(f'TARGET-{target_filename}-*.report.bin.zst'):
            runs.append((corpus, report, target, target_filename))
    max = len(runs)

    # start thread per core of host
    threads = []
    for num in range(cpu_cores()):
        t = threading.Thread(target=run_plot_data, args=(
            config_name, output, root, args.no_basic_block_filter, args.only_coverage, bug_filter, plot, runs, max))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # write plot overview
    plot['data'] = json.loads(json.dumps(plot['data'], sort_keys=True))
    open(args.plot, 'w').write(json.dumps(plot, indent=4))


def run_plot_data(config_name, output, root, no_basic_block_filter, only_coverage, bug_filter, plot, runs, max):
    while len(runs) > 0:
        (corpus, report, target, target_filename) = runs.pop(0)

        eprint('run', max - len(runs), '/', max, ':', corpus, target_filename)

        run_name = report.name.replace('.report.bin.zst', '')
        run_name_base = run_name.replace(f'{target_filename}-', '')
        run_num = '-'.join(run_name_base.split('-')[1:])
        corpus_tar = report.name.replace('.report.bin.zst', '.corpus.tar.zst')
        plot_data_dir = output / config_name
        plot_data = plot_data_dir / f'{run_name}.json.zst'

        # mkdir
        os.makedirs(plot_data_dir, exist_ok=True)

        # optional basic block filter
        if no_basic_block_filter:
            bb_filter = []
        else:
            bb_filter = [
                '--valid-basic-blocks',
                f'{HOEDUR_TARGETS}/arm/{target}/valid_basic_blocks.txt',
            ]

        # only coverage plot
        if only_coverage:
            archive = []
        else:
            archive = ['--corpus-archive', corpus / corpus_tar]

        # export data to JSON
        run(binary('hoedur-plot-data') +
            bb_filter +
            bug_filter + [
            plot_data,
            '--report',
            report
        ] + archive)

        # replace root (relative path)
        if root:
            plot_data = plot_data.relative_to(root)

        # add to plot overview
        if not config_name in plot['data']:
            plot['data'][config_name] = {}
        if not target in plot['data'][config_name]:
            plot['data'][config_name][target] = {}
        plot['data'][config_name][target][run_num] = str(plot_data)


if __name__ == '__main__':
    main()
