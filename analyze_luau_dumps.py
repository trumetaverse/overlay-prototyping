import os
import json
import argparse
import multiprocessing as mp
import asyncio
import sys
import logging
import threading
import time

from overlay_prototyping.luau_roblox.luau_roblox_analysis import LuauRobloxAnalysis

LOGGING_FORMAT = '[%(asctime)s - %(name)s] %(message)s'
LOGGER_NAME = "analyze_luau_dumps"
LOGGER = logging.getLogger(LOGGER_NAME)

LOG_FILE = 'analyze_luau_dumps.log'


def init_logger(name=LOGGER_NAME,
                log_level=logging.DEBUG,
                logging_fmt=LOGGING_FORMAT,
                log_file=LOG_FILE):
    global LOGGER
    logging.getLogger(name).setLevel(log_level)
    formatter = logging.Formatter(logging_fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(log_level)
    ch.setFormatter(formatter)
    logging.getLogger(name).addHandler(ch)
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    fh.setLevel(log_level)
    logging.getLogger(name).addHandler(fh)
    LOGGER = logging.getLogger(name)
    return logging.getLogger(name)


BASE_DIR = "E:/dumps/2023-04-28/"
BINS_DIR = os.path.join(BASE_DIR, 'bins')
MEMS_DIR = os.path.join(BASE_DIR, 'mem')
SEARCHES_DIR = os.path.join(BASE_DIR, 'searches')
DUMP_EXT = 'DMP'


def reset_global_deps(base_dir):
    global BASE_DIR, BINS_DIR, MEMS_DIR, SEARCHES_DIR
    BASE_DIR = base_dir
    BINS_DIR = os.path.join(BASE_DIR, 'bins')
    MEMS_DIR = os.path.join(BASE_DIR, 'mem')
    SEARCHES_DIR = os.path.join(BASE_DIR, 'searches')


DUMP_FMT = "{base_dir}/{bin_name}.{dmp_ext}"
LUAPAGE_POINTER_FMT = "{base_dir}/{bin_name}/luapage_comments.json"
POINTERS_FMT = "{base_dir}/{bin_name}/pointer_comments.json"
MEMORY_INFO_FMT = "{base_dir}/{bin_name}.json"

IDENTIFIED_OBJECTS_PARSE_FMT = "{base_dir}/{bin_name}/memory_ranges_roblox_assets.json"
IDENTIFIED_OBJECTS_FULL_FMT = "{base_dir}/{bin_name}/full_dump_roblox_assets.json"

SAVED_OBJECTS_FILE = "{base_dir}/{bin_name}/gcos_and_structs.json"
FULL_EXTRACTED_GAME_ASSETS_BASE = "{base_dir}/{bin_name}/extracted_assets/full/"
PARSE_EXTRACTED_GAME_ASSETS_BASE = "{base_dir}/{bin_name}/extracted_assets/parse/"


def extract_assets(asset_info_file, dmp_file, output_dir):
    print("Executing extract assets: {}".format(output_dir))
    dmp = open(dmp_file, 'rb')
    try:
        os.stat(output_dir)
    except:
        os.makedirs(output_dir, exist_ok=True)

    for asset in [json.loads(line) for line in open(asset_info_file).readlines()]:
        dmp.seek(0)
        start = asset['paddr']
        size = asset['size']
        digest = asset['digest']
        fname = os.path.join(output_dir, digest)
        dmp.seek(start)
        data = dmp.read(size)
        open(fname, 'wb').write(data)

    print("Completed executing extract assets: {}".format(output_dir))


def full_extract_downloaded_assets(bin_name):
    asset_info_file = IDENTIFIED_OBJECTS_FULL_FMT.format(**{"base_dir": SEARCHES_DIR, "bin_name": bin_name})
    dmp_file = DUMP_FMT.format(**{"base_dir": BINS_DIR, 'bin_name': bin_name, "dmp_ext": DUMP_EXT})
    output_dir = FULL_EXTRACTED_GAME_ASSETS_BASE.format(**{"base_dir": SEARCHES_DIR, "bin_name": bin_name})
    extract_assets(asset_info_file, dmp_file, output_dir)


def parse_extract_downloaded_assets(bin_name):
    asset_info_file = IDENTIFIED_OBJECTS_PARSE_FMT.format(**{"base_dir": SEARCHES_DIR, "bin_name": bin_name})
    dmp_file = DUMP_FMT.format(**{"base_dir": BINS_DIR, 'bin_name': bin_name, "dmp_ext": DUMP_EXT})
    output_dir = PARSE_EXTRACTED_GAME_ASSETS_BASE.format(**{"base_dir": SEARCHES_DIR, "bin_name": bin_name})
    extract_assets(asset_info_file, dmp_file, output_dir)

def wrapper(bin_name):
    t1 = threading.Thread(target=parse_extract_downloaded_assets, args=(bin_name,))
    t1.start()
    t2 = threading.Thread(target=full_extract_downloaded_assets, args=(bin_name,))
    t2.start()
    return [t1, t2]


def extract_relevant_data(bin_name, byfron_analysis=True, do_return=False, load_pointers=False, scan=True):
    print("here", bin_name, byfron_analysis, do_return, load_pointers)
    dmp_file = DUMP_FMT.format(**{"base_dir": BINS_DIR, 'bin_name': bin_name, "dmp_ext": DUMP_EXT})
    pointers_file = POINTERS_FMT.format(**{"base_dir": SEARCHES_DIR, 'bin_name': bin_name})
    lua_pointers_file = LUAPAGE_POINTER_FMT.format(**{"base_dir": SEARCHES_DIR, 'bin_name': bin_name})
    radare_memory_info_file = MEMORY_INFO_FMT.format(**{"base_dir": MEMS_DIR, 'bin_name': bin_name})
    saved_state = SAVED_OBJECTS_FILE.format(**{"base_dir": SEARCHES_DIR, 'bin_name': bin_name})

    threads = wrapper(bin_name)

    analysis = LuauRobloxAnalysis(dmp_file=dmp_file,
                                  radare_file_data=radare_memory_info_file,
                                  sift_results=pointers_file,
                                  luapage_pointers_file=lua_pointers_file,
                                  byfron_analysis=byfron_analysis)
    analysis.load_lua_pages()
    if scan:
        lpscan_results = analysis.scan_lua_pages_gco(add_obj=True)
        tvals = analysis.scan_lua_pages_tvalue(add_obj=True)
    if load_pointers:
        analysis.load_sift_results()
        while True:
            if analysis.check_results_status() and analysis.check_analysis_status():
                break
            time.sleep(3*60)
    analysis.save_state(saved_state)
    [t.join() for t in threads]
    if do_return:
        return analysis
    else:
        return bin_name


CNT = 0
TOTAL = 0


def log_completion(bin_name):
    global CNT, TOTAL
    CNT += 1
    LOGGER.info("Completed {} of {}, parallel extraction for {}".format(CNT, TOTAL, bin_name))


def main(bin_name=None, num_jobs=None, load_pointers=False, scan=True):
    global TOTAL
    bin_names = None
    if bin_name is None:
        bin_names = [os.path.splitext(i)[0] for i in os.listdir(BINS_DIR)]
    elif isinstance(num_jobs, int) and bin_names is None and bin_name is not None:
        bin_names = [bin_name]
    LOGGER.info("starting the extraction process for: {}".format(bin_name if bin_name else ", ".join(bin_names)))
    analysis = None

    if bin_names is None and bin_name is None:
        raise Exception("No bin_name specified for analysis")

    if isinstance(num_jobs, int) and isinstance(bin_names, list):
        LOGGER.info("performing extraction in parallel with {} jobs".format(num_jobs))
        TOTAL = len(bin_names)
        with mp.Pool(num_jobs) as pool:
            for bin in bin_names:
                pool.apply_async(extract_relevant_data, args=(bin,), kwds={'load_pointers': load_pointers, "scan": scan},
                                 callback=log_completion)
            pool.close()
            pool.join()
        return analysis

    elif bin_name is not None:
        LOGGER.info("performing single extraction for {}".format(bin_name))
        analysis = extract_relevant_data(bin_name, do_return=True, load_pointers=load_pointers, scan=scan)
        LOGGER.info("Completed single extraction for {}".format(bin_name))
    elif bin_names is not None:
        cnt = len(bin_names)
        while len(bin_names) > 0:
            completed = cnt - len(bin_names)
            bin_name = bin_names.pop()
            do_return = len(bin_names) == 0  # last bin_name in list
            LOGGER.info(
                "Completed {} of {}, performing serial extraction extraction for {}".format(completed, cnt, bin_name))
            analysis = extract_relevant_data(bin_name, do_return=do_return, load_pointers=load_pointers, scan=scan)
            LOGGER.info("Completed single extraction for {}".format(bin_name))
    return analysis


parser = argparse.ArgumentParser(
    prog='analyze_luau_dumps',
    description='extract identify and extract relevant objects from a Roblox memory dump')

parser.add_argument('-b', '--bin', help='analyze only the bin_name', type=str, default=None)
parser.add_argument('-d', '--dir', help='base directory for analysis', type=str, required=True)
parser.add_argument('-m', '--mp', help='number of concurrent processes', type=int, default=None)
parser.add_argument('-e', '--dmp_ext', help='extension of the dump file', type=str, default=DUMP_EXT)
parser.add_argument('-p', '--load_pointers', help='extension of the dump file', action="store_true", default=False)
parser.add_argument('-s', '--scan', help='scan for tvalues and gcos', action="store_true", default=False)

if __name__ == "__main__":
    init_logger()
    args = parser.parse_args()

    DUMP_EXT = args.dmp_ext
    if args.dir:
        reset_global_deps(args.dir)
    else:
        LOGGER.error("Failed to provide a working directory")

    bin_name = args.bin
    num_jobs = args.mp
    load_pointers = args.load_pointers
    scan = args.scan
    LOGGER.info("[+++] Starting analysis of {} for bin_name:{}  num_jobs:{} load_pointers:{}, scan: {}".format(args.dir, bin_name,
                                                                                                     num_jobs,
                                                                                                     load_pointers,
                                                                                                     scan))
    main(bin_name=bin_name, num_jobs=num_jobs, load_pointers=load_pointers, scan=scan)
    LOGGER.info(
        "[===] Completed analysis of {} for bin_name:{}  num_jobs:{} load_pointers:{} scan:{}".format(args.dir, bin_name,
                                                                                              num_jobs,
                                                                                              load_pointers,
                                                                                              scan))
