#!/usr/bin/env python3

import argparse
import glob
import os
from pathlib import Path
import threading

from fuzz_common import *


def main():
    parser = argparse.ArgumentParser(description='collect bug reproducers')
    parser.add_argument('output', help='output path (dir)')
    parser.add_argument('corpus', help='corpus path')
    parser.add_argument('--targets', nargs='+')
    args = parser.parse_args()

    # build
    build('hoedur-reproducer')

    # paths
    output = Path(args.output)
    corpus = Path(os.path.normpath(args.corpus))

    # runs
    runs = []
    for target in args.targets:
        target_filename = target.replace('/', '-')
        for report in corpus.glob(f'TARGET-{target_filename}-*.report.bin.zst'):
            runs.append((target, report))
    max = len(runs)

    # start thread per core of host
    threads = []
    for num in range(cpu_cores()):
        t = threading.Thread(target=run_executions,
                             args=(output, corpus, runs, max))
        t.start()
        threads.append(t)

    # join threads
    for t in threads:
        t.join()


def run_executions(output, corpus, runs, max):
    while len(runs) > 0:
        (target, report) = runs.pop(0)

        eprint('run', max - len(runs), '/', max, ':', corpus)

        basename = report.name.replace('.report.bin.zst', '')
        run_name = basename[basename.find('FUZZER'):]
        corpus_tar = f'{basename}.corpus.tar.zst'
        reproducers_dir = output / target / f'{run_name}'

        os.makedirs(reproducers_dir, exist_ok=True)

        run(binary('hoedur-reproducer') + [
            reproducers_dir,
            '--corpus-archive',
            corpus / corpus_tar,
            '--report',
            report])


if __name__ == '__main__':
    main()
