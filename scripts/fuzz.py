#!/usr/bin/env python3

import subprocess
import argparse
import glob
import os

from fuzz_common import *


def main():
    parser = argparse.ArgumentParser(description='run fuzz eval')
    parser.add_argument('target', help='target name, e.g. P2IM/CNC')
    parser.add_argument('--corpus', default='corpus')
    parser.add_argument('--fuzzer', default='hoedur', choices=FUZZER)
    parser.add_argument('--models', action='store_true')
    parser.add_argument('--fuzzware', action='store_true')
    parser.add_argument('--no-statistics', action='store_true')
    parser.add_argument('--duration', default='24h')
    parser.add_argument('--run', type=int, default=1)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--log', action='store_true')
    args = parser.parse_args()

    do_fuzzer_run(args.corpus, args.target, args.fuzzer, args.models, args.fuzzware,
                  not args.no_statistics, args.duration, args.run, args.overwrite, args.trace, args.log)


def do_fuzzer_run(corpus_base, target, fuzzer, models, fuzzware, statistics, duration, run_id, overwrite, trace, log):
    corpus, hoedur = init_hoedur(
        corpus_base, target, fuzzer, models, fuzzware, duration, run_id, overwrite)

    # run fuzzer
    print(f'running fuzzer {fuzzer} for {duration} with run id {run_id} ...')

    cmd = hoedur + ['fuzz', '--archive-dir', corpus_base]

    if statistics:
        cmd += ['--statistics']

    try:
        run(cmd, log, f'{corpus}.log', timeout=parse_duration(duration))
    except subprocess.TimeoutExpired:
        pass

    print('fuzzer run done')

    # collect coverage
    archive = corpus + '.corpus.tar.zst'
    do_run_cov(archive, fuzzer, target, corpus, trace, log)


def do_run_cov(archive, fuzzer, target, corpus, trace, log):
    # use archive
    hoedur = init_hoedur_import_config(fuzzer, archive)

    # enable debug / trace
    cmd = hoedur + [
        '--debug',
        '--trace'
    ]
    if trace:
        cmd += ['--trace-file', corpus + '.trace.bin.zst']

    # add hooks
    for hook in glob.iglob('{}/{}/{}/hook*.rn'.format(HOEDUR_TARGETS, HOEDUR_ARCH, target)):
        cmd += ['--hook', hook]

    # run-cov
    cmd += [
        'run-cov',
        corpus + '.report.bin.zst',
        corpus + '.corpus.tar.zst'
    ]

    print('collecting coverage ...')
    run(cmd, log, f'{corpus}.cov.log')


if __name__ == '__main__':
    main()
