#!/usr/bin/env python3

import argparse
import glob
import os
from pathlib import Path
import threading

from fuzz_common import *


def main():
    parser = argparse.ArgumentParser(description='collect executions data')
    parser.add_argument('output', help='output path (dir)')
    parser.add_argument('summary', help='output summary path')
    parser.add_argument('corpus', help='corpus path')
    parser.add_argument('--targets', nargs='+')
    args = parser.parse_args()

    # build
    build('hoedur-eval-executions')

    # paths
    output = Path(args.output)
    corpus = Path(os.path.normpath(args.corpus))

    # runs
    runs = []
    for target in args.targets:
        target_filename = target.replace('/', '-')
        for report in corpus.glob(f'TARGET-{target_filename}-*.report.bin.zst'):
            runs.append((corpus, report))
    max = len(runs)

    # start thread per core of host
    threads = []
    for num in range(cpu_cores()):
        t = threading.Thread(target=run_executions, args=(output, runs, max))
        t.start()
        threads.append(t)

    # join threads
    for t in threads:
        t.join()

    # collect execution summary
    summary = open(args.summary, 'w')
    for target in args.targets:
        # collect executions files
        target_filename = target.replace('/', '-')
        executions = glob.glob(f'{output}/TARGET-{target_filename}-*.txt')
        executions.sort()

        # total executions + duration
        total_executions = 0
        total_duration = 0
        for path in executions:
            for line in open(path, 'r').readlines():
                # strip line
                line = line.lstrip().rstrip()

                # skip comment
                if line.startswith('#'):
                    continue

                # fuzz_duration total_executions execs/s
                data = line.split('\t')
                if len(data) == 3:
                    total_duration += int(data[0])
                    total_executions += int(data[1])

        # calculate total execs/s
        if total_duration > 0:
            execs = round(total_executions / total_duration, 2)
        else:
            execs = 0

        summary.write(f'{target}\t{execs}\n')
    summary.close()


def run_executions(output, runs, max):
    while len(runs) > 0:
        (corpus, report) = runs.pop(0)

        eprint('run', max - len(runs), '/', max, ':', corpus)

        run_name = report.name.replace('.report.bin.zst', '')
        corpus_tar = report.name.replace('.report.bin.zst', '.corpus.tar.zst')
        plot_data = output / f'{run_name}.txt'

        run(binary('hoedur-eval-executions') + [
            plot_data,
            corpus / corpus_tar])


if __name__ == '__main__':
    main()
