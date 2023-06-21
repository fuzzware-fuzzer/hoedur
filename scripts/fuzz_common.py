#!/usr/bin/env python3

import os
import shutil
import psutil
import subprocess
import sys
import threading


def env(var, default=None):
    return os.environ.get(var) or default


SCRIPTS_DIR = os.path.dirname(os.path.realpath(__file__))
CARGO_BIN = env('HOME', '/home/user') + '/.cargo/bin'
CODE = env('CODE', env('HOME'))
HOEDUR_BIN = env('HOEDUR_BIN', 'hoedur')
HOEDUR_ARCH = env('HOEDUR_ARCH', 'arm')
HOEDUR_TARGETS = env('HOEDUR_TARGETS', CODE + '/hoedur-targets')
HOEDUR_FUZZER_CONFIG = env('HOEDUR_FUZZER_CONFIG',
                           CODE + '/hoedur-fuzzer-config')
CONFIG_FILE = env('CONFIG_FILE', 'config.yml')
MODELS_FILE = env('MODELS_FILE', 'models.yml.zst')

FUZZER = {
    'hoedur': f'{HOEDUR_BIN}-{HOEDUR_ARCH}',
    'hoedur-single-stream': f'{HOEDUR_BIN}-single-stream-{HOEDUR_ARCH}',
    'hoedur-dict': f'{HOEDUR_BIN}-dict-{HOEDUR_ARCH}',
    'hoedur-single-stream-dict': f'{HOEDUR_BIN}-single-stream-dict-{HOEDUR_ARCH}',
}
MODES = ['plain', 'models', 'fuzzware']

BUILD_MUTEX = threading.Lock()


def init():
    if not env('LD_LIBRARY_PATH'):
        os.environ['LD_LIBRARY_PATH'] = CARGO_BIN


def cpu_cores(logical=True):
    return psutil.cpu_count(logical=logical)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def build(binary, crate='hoedur-analyze', force_build=False):
    global BUILD_MUTEX
    BUILD_MUTEX.acquire()

    # check if binary is available (e.g. in hoedur docker container)
    if not force_build:
        try:
            subprocess.check_call([binary, '--help'],
                                  stdout=subprocess.DEVNULL)
        except:
            force_build = True

    # build binary
    if force_build:
        run([
            'cargo', 'install', '--path', crate, '--bin', binary
        ])

    BUILD_MUTEX.release()

    return force_build


def binary(cmd):
    return [cmd]


def run(cmd, log=None, logfile=None, timeout=None, **kwargs):
    eprint(
        f'running {cmd}, log = {log}, logfile = {logfile}, timeout = {timeout} ...')

    # log / logfile
    if log == False:
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL
    elif log:
        if logfile is not None:
            log = logfile

        stdout = open(log, 'wb')
        stderr = subprocess.STDOUT
    else:
        stdout = None
        stderr = None

    # exec
    p = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, **kwargs)

    # terminate after timeout
    try:
        return p.wait(timeout)
    except subprocess.TimeoutExpired:
        p.terminate()

    # try second terminate after graceperiod
    try:
        return p.wait(timeout=10 * 60)
    except subprocess.TimeoutExpired:
        p.terminate()

    # kill after another graceperiod
    try:
        return p.wait(timeout=10 * 60)
    except subprocess.TimeoutExpired as e:
        p.kill()
        eprint('ERROR: process', cmd[0], 'did not terminate')
        raise e


def parse_duration(value):
    if 's' in value:
        value = int(value.rstrip('s'))
    elif 'm' in value:
        value = int(value.rstrip('m')) * 60
    elif 'h' in value:
        value = int(value.rstrip('h')) * 60 * 60
    elif 'd' in value:
        value = int(value.rstrip('d')) * 60 * 60 * 24
    else:
        eprint('ERROR: unknown duration format')
        assert False

    return value


class CorpusExistsException(Exception):
    def __init__(self, path):
        self.path = path

    def __str__(self) -> str:
        return f'ERROR: corpus already exists: {self.path}'


def init_hoedur(corpus_base, target, fuzzer, models, fuzzware, duration, run_id, overwrite):
    init()

    modes = ''
    if models:
        modes += '-models'
    if fuzzware:
        modes += '-fuzzware'
    if modes == '':
        modes += '-plain'

    target_name = target.replace('/', '-')

    name = f'TARGET-{target_name}-FUZZER-{fuzzer}-RUN-{run_id:02d}-DURATION-{duration}-MODE{modes}'
    target_dir = '{}/{}/{}'.format(HOEDUR_TARGETS, HOEDUR_ARCH, target)
    corpus = corpus_base + '/' + name
    corpus_tar = f'{corpus}.corpus.tar.zst'

    eprint('name =', name)
    eprint('corpus =', corpus)
    eprint('target_dir =', target_dir)

    os.makedirs(corpus_base, exist_ok=True)

    if os.path.isdir(corpus) and not overwrite:
        raise CorpusExistsException(corpus)
    elif os.path.isfile(corpus_tar) and not overwrite:
        raise CorpusExistsException(corpus_tar)

    # make sure hoedur is built
    build_hoedur(fuzzer)

    hoedur = [
        FUZZER[fuzzer],
        '--name', name,
        '--config', f'{target_dir}/{CONFIG_FILE}'
    ]

    if models:
        hoedur += ['--models', f'{target_dir}/{MODELS_FILE}']

    if fuzzware:
        # create model share folder
        model_share = f'{corpus_base}/model-share-{target_name}'
        os.makedirs(model_share, exist_ok=True)

        # enable fuzzware modeling
        hoedur += ['--fuzzware', '--model-share', model_share]

    return corpus, hoedur


def init_hoedur_import_config(fuzzer, archive):
    init()
    build_hoedur(fuzzer)
    basename = os.path.basename(archive).replace('.corpus.tar.zst', '')
    return [FUZZER[fuzzer], '--name', basename, '--import-config', archive]


def build_hoedur(fuzzer):
    binary = FUZZER[fuzzer]

    # build binary
    if build(binary, 'hoedur'):
        # copy library
        shutil.copyfile(
            f'{SCRIPTS_DIR}/../target/release/libqemu-system-arm.release.so',
            f'{CARGO_BIN}/libqemu-system-arm.release.so'
        )
