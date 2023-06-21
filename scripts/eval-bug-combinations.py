#!/usr/bin/env python3

import argparse
import glob
import os
import threading

from fuzz_common import *

BUG_COMBINATION_YAML_NAME_FORMAT = "bug-combinations-run-{:02d}.yml"


def main():
    parser = argparse.ArgumentParser(
        description='Collect bug combinations per (crashing) corpus input')
    parser.add_argument('corpus')
    parser.add_argument('--output', required=True,
                        help="Output base directory. Results will be placed in <outdir>/path/to/target/bug-combinations-run-*.yml")
    parser.add_argument('--targets', nargs='+')
    parser.add_argument('--cores', type=int, default=cpu_cores(logical=True))
    args = parser.parse_args()

    if not os.path.exists(args.corpus):
        eprint("[-] corpus directory does not exist")
        exit(1)

    # build
    build('hoedur-eval-crash')

    threads = []
    workloads = []

    for target in args.targets:
        bug_combination_outdir = os.path.join(args.output, target)
        os.makedirs(bug_combination_outdir, exist_ok=True)

        # collect reports
        reports = glob.glob(
            '{}/TARGET-{}-*.report.bin.zst'.format(args.corpus, target.replace('/', '-')))
        reports.sort()

        for i, report in enumerate(reports):
            outfile = os.path.join(
                bug_combination_outdir, BUG_COMBINATION_YAML_NAME_FORMAT.format(i+1))
            workloads.append((report, outfile))

    max = len(workloads)

    # start threads
    for _ in range(args.cores):
        t = threading.Thread(target=crash_time, args=(workloads, max))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


def crash_time(workloads, max):
    while len(workloads) > 0:
        # next target
        report, outpath = workloads.pop(0)
        eprint('run', max - len(workloads), '/', max, ':', report)

        with open(outpath, "w") as f:
            # collect crash timings in report group
            subprocess.run(
                binary('hoedur-eval-crash') + ['--yaml', report], stdout=f)

        eprint('done', report)


if __name__ == '__main__':
    main()
