#!/usr/bin/env python3

import argparse
import subprocess
import threading
import time

from fuzz_common import *
from fuzz import do_fuzzer_run


def main():
    parser = argparse.ArgumentParser(description='run fuzz eval on local host')
    parser.add_argument('--runs', type=int, default=4)
    parser.add_argument('--run-list', type=int, nargs='+', default=[])
    parser.add_argument('--fuzzers', nargs='+',
                        default=['hoedur'], choices=FUZZER)
    parser.add_argument('--modes', nargs='+',
                        default=['fuzzware'], choices=MODES)
    parser.add_argument('--targets', nargs='+')
    parser.add_argument('--duration', default='24h')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--log', action='store_true')
    parser.add_argument('--name', default='run')
    parser.add_argument('--cores', type=int, default=cpu_cores(logical=False))
    args = parser.parse_args()

    if len(args.run_list) > 0:
        runs = args.run_list
    else:
        runs = [run for run in range(1, args.runs+1)]

    do_local_fuzzer_run(args.cores, args.name, args.targets,
                        runs, args.fuzzers, args.modes, args.duration, args.trace, args.log)


def local_runner(core, cores, fuzz_runs, max):
    eprint(core, 'start')

    while len(fuzz_runs) > 0:
        # wait for exisiting fuzzing runs
        pids = []
        try:
            output = subprocess.check_output(['pgrep', 'hoedur']).splitlines()
        except Exception as e:
            output = []
        for line in output:
            if len(line) > 0:
                pids.append(int(line))

        if len(pids) >= cores:
            eprint(core, 'wait')
            time.sleep(30)
            continue

        # recheck to decrease race condition
        if len(fuzz_runs) < 1:
            break

        # do next fuzzing run
        fuzz_args = fuzz_runs.pop(0)
        print(core, 'run', max - len(fuzz_runs), '/', max, ':', fuzz_args)
        try:
            do_fuzzer_run(*fuzz_args)
        except CorpusExistsException as e:
            eprint(e)
        eprint(core, 'done', fuzz_args)


def do_local_fuzzer_run(cores, name, targets, runs, fuzzers, modes, duration, trace, log):
    fuzz_runs = []

    # collect mode arguments
    mode_args = []
    for mode in modes:
        # mode parts
        parts = mode.split('-')
        parts.sort()

        # convert to args
        args = [False, False]

        if 'models' in parts:
            args[0] = True
        if 'fuzzware' in parts:
            args[1] = True

        # validate modes
        if mode != 'plain':
            if len(parts) != len([arg for arg in args if arg]):
                eprint('unknown mode(s):', mode)
                assert (False)

        mode_args.append(tuple(args))

    # collect list of fuzz runs
    for fuzzer in fuzzers:
        for target in targets:
            for (models, fuzzware) in mode_args:
                for run in runs:
                    fuzz_args = (
                        'corpus/{}-{}/'.format(name, fuzzer),
                        target,
                        fuzzer,
                        models,
                        fuzzware,
                        True,
                        duration,
                        run,
                        False,
                        trace,
                        log
                    )

                    fuzz_runs.append(
                        fuzz_args
                    )
    max = len(fuzz_runs)

    # start thread per core
    threads = []

    for core in range(cores):
        t = threading.Thread(target=local_runner,
                             args=(core, cores, fuzz_runs, max))
        t.start()
        threads.append(t)

        time.sleep(1)

    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
