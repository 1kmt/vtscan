#!/usr/bin/env python3

__description__ = """
Get a file report of suspicious files via VirusTotal API.
It queries the hash value of the specified file and all files contained in the specified directory.
It can also upload suspicious files.
"""
__date__ = "2022/09/05"
__version__ = "2.1.5"
__author__ = "ikmt"

"""
_________________________________________________________________
Need packages for working
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
python -m pip install requests
python -m pip install selenium
python -m pip install webdriver_manager
  if you get an error
    python -m pip install --upgrade [pip|requests|selenium|webdriver_manager]
_________________________________________________________________
Required version of Python
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Available since Python 3.6
v3.6 - formatted string literal (f-string)
v3.5 - os.listdir(), os.scandir()
v3.2 - logging.Formatter() (Changed in version 3.2:added style parameter)
_________________________________________________________________
Test environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
OS: windows 10
pip version: 20.0.2
Python version: 3.7.6
_________________________________________________________________
Command line examples
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
python vtscan.py -i ./filename -k apikey
python vtscan.py -i ./dirname1 ./dirname2/filename -k apikey -o ./dirname3
python vtscan.py -i ./dirname -k apikey -u -w 0
python vtscan.py -i ./dirname/filename -k apikey -u -s detection, summary -z
_________________________________________________________________
Changelog
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2022-09-05 v2.1.5 added size limit process (650MB)
2022-09-04 v2.1.4 deleted permalink item from csv file
2022-09-03 v2.1.3 changed command line argument options(-i option, nargs)
2022-09-02 v2.1.2 fixed API key check process
2022-08-24 v2.1.1 changed -s (screenshot) option (Individually selectable)
2022-08-24 v2.1.0 added -j (json) option (Save response data in JSON format)
2022-08-22 v2.0.0 changed from VirusTotal APIv2 to VirusTotal APIv3
2022-08-04 v1.4.0 added -s (screenshot) option and -z (browser) option
2022-07-28 v1.3.1 fixed log output format
2022-04-27 v1.3.0 changed -u (upload) option (Upload files smaller than 200MB)
2022-04-18 v1.2.0 added -u (upload) option (Upload files smaller than 32MB)
2022-04-12 v1.1.0 changed CSV format
2022-03-09 v1.0.0 release
"""

import argparse
import csv
import datetime
import hashlib
import json
import logging
import os
import re
import requests
import sys
import time
import webbrowser

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urljoin


# Constants
# If a value is set using an option, the value of the option is used
SCRIPT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
OUTPUT_BASE_PATH = os.path.expanduser("~/Desktop")
OUTPUT_DIR_NAME = "vt"
LOG_FILE_NAME ="virustotal.log"
CSV_FILE_NAME ="virustotal.csv"
MAX_WAITING_TIME = 17
MIN_WAITING_TIME = 0
MAX_NUM_TRIALS = 6
# Public API key:15, Private API key(premium customers):0
WAITING_TIME = 15
# Used when hardcoding the API key
VT_API_KEY = "Your API key"
# Field name in csv file
CSV_FIELD_NAMES = [
    "seq_num",
    # The following are properties retrieved from the file
    "file_name",
    "file_path",
    "file_size",
    "md5",
    "sha1",
    "sha256",
    "access_time",
    "change_time",
    "modify_time",
    # The following is the status of script processing
    # If you uploaded the file, be sure to check the result of 'last_analysis_status'
    # If the 'last_analysis_status' is 'queued', the scan may not have completed
    "status_code",
    "status_message",
    "last_analysis_status",
    # The following is information from the file report
    "last_analysis_date",
    "first_submission_date",
    "times_submitted",
    "type_description",
    "trid",
    "magic",
    "meaningful_name",
    "reputation",
    "stats_malicious",
    "stats_undetected",
    "stats_harmless",
    "stats_suspicious",
    "stats_total",
    "detected_malicious",
    "detected_suspicious",
    "sandbox",
    "signature_product",
    "signature_verified",
    "signature_description",
    "signature_signers",
    "signature_copyright",
    "votes_harmless",
    "votes_malicious"
]


# Configuring logging
log_format_string = "{asctime}[{levelname:.1}] {message}"
date_format_string = "%Y-%m-%d %H:%M:%S"
formatter = logging.Formatter(
    style="{",
    fmt=log_format_string,
    datefmt=date_format_string
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


"""
_________________________________________________________________
List of functions and classes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Function
  - main():
  - check_argument():
  - get_file_list(path_list):
  - create_dir(dir_path, interactive=True):
  - get_files(path_list, recursive=True):
  - get_properties(file_path):
  - get_file_hash(file):
  x write_label_and_dic_to_csv(label, csv_data, file_path):
  - write_dic_to_csv(label, csv_data, file_path):
  - write_list_to_csv(csv_data, file_path):
  - write_response_dict(response_dict, file_path):
  - take_screeshot(id:str, dir_path):
  - open_webpage(id:str):
  x shutdown_logger_handler(logger):
Class
  - VirusTotalAPIv3
  - WebScreenshot
"""
def main():
    global webshot
    # Output log to terminal
    log_stream_handler = logging.StreamHandler()
    log_stream_handler.setFormatter(formatter)
    logger.addHandler(log_stream_handler)
    # Check command line arguments
    args = check_argument()
    sleep_time = args.wait
    api_key = args.apikey
    # Get list of suspicious files
    files = get_file_list(args.input)
    # Create working directory
    work_dir = create_dir(args.output, args.batch)
    # Create a log file
    log_file_path = os.path.abspath(os.path.join(work_dir, LOG_FILE_NAME))
    log_file_handler = logging.FileHandler(filename=log_file_path)
    log_file_handler.setFormatter(formatter)
    logger.addHandler(log_file_handler)
    # Create a CSV file
    file_path = os.path.abspath(os.path.join(work_dir, CSV_FILE_NAME))
    write_list_to_csv(CSV_FIELD_NAMES, file_path)
    # Change current directory
    save_current_path = os.getcwd()
    os.chdir(work_dir)
    # Class instances
    vt = VirusTotalAPIv3(api_key)
    vt.sleep_time = sleep_time
    vt.max_attempts = MAX_NUM_TRIALS
    if(args.screenshot is not None):
        webshot = WebScreenshot()
    # Save processing results
    statistics = dict.fromkeys([
        "vt_total",
        "vt_failure",
        "vt_queued",
        "sc_failure",
    ], 0)
    statistics["vt_total"] = len(files)
    # Start message
    logger.info(f"[{'START':<9}] {__file__}")

    for i in range(0, statistics["vt_total"]):
        properties = {"seq_num": i + 1}
        properties.update(get_properties(files[i]))
        logger.info(f"[{'IDX/TOTAL':<9}] {i + 1:05}/{statistics['vt_total']:05}")
        logger.info(f"[{'PATH,MD5':<9}] {properties['file_path']},{properties['md5']}")

        if(i > 0):
            vt.pause(sleep_time)
        response_dict = vt.get_files(properties["md5"])

        # The -u option to upload and scan the file is specified
        if(args.upload and response_dict.temp_data.status_code == 404):
            vt.pause(sleep_time)
            response_dict = vt.upload_files(properties["file_path"])
            if(response_dict.temp_data.status_code == 200):
                vt.pause(sleep_time)
                last_analysis_status = vt.check_analysis_status(response_dict.data.id)
                vt.pause(sleep_time)
                response_dict = vt.get_files(properties["md5"])
            else:
                last_analysis_status = "failed"

            response_dict.temp_data.update({
                "last_analysis_status": last_analysis_status
            })

            if(last_analysis_status == "queued"):
                statistics["vt_queued"] += 1

        report = vt.normalize_data(response_dict)
        properties.update(report)
        write_dic_to_csv(properties.keys(), properties, file_path)

        if(not args.upload 
            and report["status_code"] != 200 
            and report["status_code"] != 404):
            statistics["vt_failure"] += 1
        elif(args.upload
            and (report["status_code"] != 200
            or report["last_analysis_status"] == "failed")):
            statistics["vt_failure"] += 1

        # Create separate directories to store individual data
        if(args.screenshot is not None or args.json):
            dir_name = str(properties["seq_num"]).zfill(5)
            dir_name += "_" + properties["file_name"]
            dir_name += "_" + properties["md5"]
            separate_dir = create_dir(os.path.join(work_dir, dir_name), batch=True)

        # The -j option for storing response data is specified
        if(args.json):
            json_path = os.path.join(separate_dir, "extended_response.json")
            write_response_dict(response_dict, json_path)

        # The -s option to take screenshots is specified
        if(args.screenshot is not None):
            status = take_screeshot(properties["sha256"], args.screenshot, separate_dir)
            if(False in status.values()):
                statistics["sc_failure"] += 1

        # The -z option to open in browser is specified
        if(args.browser):
            open_webpage(properties["sha256"])

    # Result
    logger.info(f"[{'RSLT_REPT':<9}] TOTAL:{statistics['vt_total']:^5}"
        + f",SUCCESS(queued):{statistics['vt_total'] - statistics['vt_failure']:^5}"
        + f"({statistics['vt_queued']:^5})"
        + f",FAILURE:{statistics['vt_failure']:^5}")
    if(args.screenshot is not None):
        logger.info(f"[{'RSLT_SS':<9}] TOTAL:{statistics['vt_total']:^5}"
            + f",{'SUCCESS':15}:{statistics['vt_total'] - statistics['sc_failure']:^5}{'':7}"
            + f",FAILURE:{statistics['sc_failure']:^5}")

    # Close Webdriver 
    if(args.screenshot is not None):
        webshot.close()
    # End message
    logger.info(f"[{'END':<9}] {__file__}")

    return 0


def check_argument():
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument("-b", "--batch",
        action="store_true",
        help="disable interactive mode"
    )
    parser.add_argument("-i", "--input",
        type=str,
        nargs='+',
        required=True, 
        help="suspicious file or directory containing suspicious files"
    )
    parser.add_argument("-j", "--json",
        action="store_true",
        help="save response data in JSON format"
    )
    parser.add_argument("-k", "--apikey",
        type=str,
        default=VT_API_KEY,
        help="specify your API key"
    )
    parser.add_argument("-o", "--output",
        type=str,
        help="change the output directory"
    )
    parser.add_argument("-s", "--screenshot",
        type=str,
        choices=[
            "detection", "summary", "details", "relations", "behavior", "community"
            #"content", "submissions", "related_iocs", "newbehavior"
        ],
        nargs='+',
        help="take a screenshot of the VirusTotal detection page, etc"
    )
    parser.add_argument("-u", "--upload",
        action="store_true",
        help="upload and scan a file"
    )
    parser.add_argument("-v", "--version",
        action="version",
        version="%(prog)s " + __version__
    )
    parser.add_argument("-w", "--wait",
        type=int,
        choices=range(MIN_WAITING_TIME, MAX_WAITING_TIME+1),
        default=WAITING_TIME,
        help="specify the waiting time for the next request"
    )
    parser.add_argument("-z", "--browser",
        action="store_true",
        help="open permalink in browser"
    )
    args = parser.parse_args()

    # Upload notice message
    if(args.upload and not args.batch):
        logger.info("+" + "-"*25 + f"{'NOTICE':^9}" + "-"*25 + "+")
        logger.info(f"| {'The -u option to upload and scan the file is specified.':<57} |")
        logger.info(f"| {'Make sure the all files does not contain sensitive data.':<57} |")
        logger.info("+" + "-"*59 + "+")
        now = datetime.datetime.now()
        date_string = now.strftime("%Y-%m-%d %H:%M:%S")
        input_text = input(date_string + "[I] Do you want to continue?(Y or N) >")
        input_text = input_text.lower()
        if(input_text != "y"):
            logger.info("Exit to the program.")
            sys.exit(-1)

    # Check sleep time range
    if(args.wait < MIN_WAITING_TIME or MAX_WAITING_TIME < args.wait):
        logger.error("Invalid sleep time.")
        logger.error(f"Specify from {MIN_WAITING_TIME} to {MAX_WAITING_TIME}.")
        sys.exit(-2)

    # Check API key format
    if(len(args.apikey) < 64  or not len(re.findall("[a-fA-F0-9]{64}", args.apikey)[0]) == 64):
        logger.error("Invalid API key.")
        sys.exit(-2)

    return args


def get_file_list(path_list):
    files = get_files(path_list)
    if(files is None):
        logger.error("The input file path (-i option) is not valid.")
        sys.exit(-2)
    elif(len(files) <= 0):
        logger.error("Suspicious file does not exist in the specified directory.")
        sys.exit(-2)
    
    return files


def create_dir(dir_path, batch=False):
    """Create a directory
    Create a working directory or separate directory.
    """
    abs_dir_path = ""
    if(dir_path):
        abs_dir_path = os.path.abspath(dir_path)
    else:
        dt = datetime.datetime.today()
        now = dt.strftime("%Y%m%d_%Hh%Mm%S")
        path = os.path.join(OUTPUT_BASE_PATH, OUTPUT_DIR_NAME + "_" + now)
        abs_dir_path = os.path.abspath(path)

    if(os.path.isfile(abs_dir_path)):
        logger.error("Please change the output directory. File already exists.")
        sys.exit(-2)
    elif(os.path.isdir(abs_dir_path)):
        if(len(os.listdir(abs_dir_path)) > 0 and not batch):
            logger.info(f"The working directory ({abs_dir_path}) already exists.")
            logger.info("And the directory is not empty.")
            now = datetime.datetime.now()
            date_string = now.strftime("%Y-%m-%d %H:%M:%S")
            input_text = input(date_string + "[I] Do you want to continue?(Y or N) >")
            input_text = input_text.lower()
            if(input_text != "y"):
                logger.info("Exit to the program.")
                sys.exit(-1)
    else:
        os.makedirs(abs_dir_path)
    
    return abs_dir_path


def get_files(path_list, recursive=True):
    if(isinstance(path_list, str)):
        path_list = [path_list]

    files = []
    # Recursive directory listing
    def search_sub_dir(path):
        with os.scandir(path) as it:
            for entry in it:
                if(not entry.name.startswith(".") and entry.is_file()):
                    files.extend([entry.path])
                elif(not entry.name.startswith(".") and entry.is_dir()):
                    if(recursive):
                        search_sub_dir(entry.path)

    for path in path_list:
        absolute_path = os.path.abspath(path)
        if(os.path.isfile(absolute_path)):
            files.extend([absolute_path])
        elif(os.path.isdir(absolute_path)):
                search_sub_dir(absolute_path)
        else:
            files = None
            break

    return files


def get_properties(file_path):
    try:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        md5, sha1, sha256 = get_file_hash(file_path)
        # Put a space at the beginning of strftime() to prevent misconversion.
        access_time = datetime.datetime.fromtimestamp(
            os.path.getatime(file_path)).strftime(" %Y-%m-%d %H:%M:%S%z")
        change_time = datetime.datetime.fromtimestamp(
            os.path.getctime(file_path)).strftime(" %Y-%m-%d %H:%M:%S%z")
        modify_time = datetime.datetime.fromtimestamp(
            os.path.getmtime(file_path)).strftime(" %Y-%m-%d %H:%M:%S%z")
    except FileNotFoundError:
        logger.error(f"FileNotFoundError:{file_path}")
        raise
    except PermissionError:
        logger.error(f"PermissionError:{file_path}")
        raise
    except OSError:
        logger.error(f"OSError:{file_path}")
        raise
    
    properties = {
        "file_name": file_name,
        "file_path": file_path,
        "file_size": file_size,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "access_time": access_time,
        "change_time": change_time,
        "modify_time": modify_time
    }

    return properties


def get_file_hash(file_path):
    try:
        with open(file_path, "rb") as rfp:
            data = rfp.read()
    except FileNotFoundError:
        logger.error(f"FileNotFoundError:{file_path}")
        raise
    except PermissionError:
        logger.error(f"PermissionError:{file_path}")
        raise
    except OSError:
        logger.error(f"OSError:{file_path}")
        raise

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    return md5, sha1, sha256


def write_label_and_dic_to_csv(label, csv_data, file_path):
    try:
        with open(file_path, "a", encoding="utf-8_sig") as wfp:
            writer = csv.DictWriter(wfp, fieldnames=label, lineterminator="\n")
            writer.writeheader()
            writer.writerows(csv_data)
    except FileNotFoundError:
        logger.error(f"FileNotFoundError:{file_path}")
        raise
    except OSError:
        logger.error(f"OSError:{file_path}")
        raise


def write_dic_to_csv(label, csv_data, file_path):
    try:
        with open(file_path, "a", encoding="utf-8_sig") as wfp:
            writer = csv.DictWriter(wfp, fieldnames=label, lineterminator="\n")
            writer.writerow(csv_data)
    except FileNotFoundError:
        logger.error(f"FileNotFoundError:{file_path}")
        raise
    except OSError:
        logger.error(f"OSError:{file_path}")
        raise


def write_list_to_csv(csv_data, file_path):
    try:
        with open(file_path, "a", encoding="utf-8_sig") as wfp:
            writer = csv.writer(wfp, lineterminator="\n")
            writer.writerow(csv_data)
    except FileNotFoundError:
        logger.error(f"FileNotFoundError:{file_path}")
        raise
    except OSError:
        logger.error(f"OSError:{file_path}")
        raise


def write_response_dict(response_dict, file_path):
    try:
        with open(file_path, "w", encoding='utf-8') as wfp:
            # Adjust the output format(indent=4)
            json.dump(response_dict, wfp, indent=4)
    except FileNotFoundError:
        logger.error(f"FileNotFoundError:{file_path}")
        raise
    except OSError:
        logger.error(f"OSError:{file_path}")
        raise


def take_screeshot(id:str, data_routes:list, dir_path):
    global webshot

    base_url = "https://www.virustotal.com/gui/file/{id}/"
    status = dict.fromkeys(data_routes, None)
    # Create url by concatenating path parameters.
    url_list = list(map(lambda x: urljoin(base_url.format_map({"id": id}), x), data_routes))
    url_list_length = len(url_list)
    for i in range(0, url_list_length):
        img_file_path = os.path.join(dir_path, "vt_" + data_routes[i] + ".png")
        status[data_routes[i]] = webshot.screenshot(url_list[i], img_file_path)
        
    return status


def open_webpage(id:str):
    base_url = "https://www.virustotal.com/gui/file/{id}/"
    url = base_url.format_map({"id": id})
    logger.info(f"[{'PROC':<9}] OPEN WEB PAGE IN BROWSER")
    logger.info(f"[{'ACCESS_PG':<9}] {url}")
    status = webbrowser.open(url, new=0, autoraise=True)


def shutdown_logger_handler(logger):
    """Manual shutdown of logs.

    If the manual page is correct, then manual execution should not be necessary 
    since the logging.shutdown() is registered in the atexit.
    atexit is also executed when an exception occurs.

    logging.shutdown()
    Informs the logging system to perform an orderly shutdown 
    by flushing and closing all handlers. ...
    When the logging module is imported, 
    it registers this function as an exit handler (see atexit),
    so normally there’s no need to do that manually.
    """
    handlers = logger.handlers[:]
    for handler in handlers:
        try:
            handler.acquire()
            handler.flush()
            handler.close()
        except(OSError, ValueError):
            pass
        finally:
            handler.release()

        logger.removeHandler(handler)


class VirusTotalAPIv3:
    """Class for handling VirusTotal APIv3
    Only the minimum required functionality is implemented.
    _________________________________________________________________
    Need packages for working::
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    python -m pip install requests
    _________________________________________________________________
    Import module in Python
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    import datetime
    import json
    import logging
    import os
    import requests
    import time
    _________________________________________________________________
    Class summary
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    Constructor
      - __init__(
            self,
            key=None,
            sleep_time=15,
            max_attempts=6,
            logger_name=__name__ + ".VirusTotal"
        ):
        :param key: Your API key
        :param sleep_time: Wait time until next request
        :param max_attempts: Maximum number of iterations when request fails
        :param logger_name: Specify private logger name for class
    Property
      - GET_FILES
      - GET_UPLOAD_URL
      - GET_ANALYSES
      - POST_FILES
      - headers
      - sleep_time
      - max_attempts
      - logger
    Method
      - map_endpoint(endpoint, map_dict:dict):
      - pause(self, sleep_time):
      - get_files(self, id):
      - get_upload_url(self):
      - get_analysis(self, id):
      - post_files(self, endpoint, files):
      - upload_files(self, file_path):
      - check_analysis_status(self, id):
      - reget(self, endpoint):
      - repost(self, endpoint, files=None, json=None):
      - convert_response_to_dict(self, response):
      - check_http_status_code(response_dict):
      - normalize_data(response_dict):
      - getSeverity(level):
    Class
      - DotDict(dict):
    """
    def __init__(
            self,
            key=None,
            sleep_time=15,
            max_attempts=6,
            logger_name=__name__ + ".VirusTotal"
    ):
        self._headers = {
            "x-apikey": key,
            "Accept": "application/json"
        }
        self._sleep_time = sleep_time
        self._max_attempts = max_attempts
        self._logger = logging.getLogger(logger_name)

        self._SLEEPING_TIME_FOR_ANALYSIS = 50
        # The following constants are used in combination with str.format_map(mapping).
        # Note:API endpoint must be "files", not "files/"
        self._ENDPOINT_BASE = "https://www.virustotal.com/api/v3/"
        self._ENDPOINT_GET_FILES = self._ENDPOINT_BASE + "files/{id}"
        self._ENDPOINT_GET_UPLOAD_URL = self._ENDPOINT_BASE + "files/upload_url"
        self._ENDPOINT_GET_ANALYSES = self._ENDPOINT_BASE + "analyses/{id}"
        self._ENDPOINT_POST_FILES = self._ENDPOINT_BASE + "files"

    @property
    def GET_FILES(self):
        return self._ENDPOINT_GET_FILES
    
    @property
    def GET_UPLOAD_URL(self):
        return self._ENDPOINT_GET_UPLOAD_URL
    
    @property
    def GET_ANALYSES(self):
        return self._ENDPOINT_GET_ANALYSES

    @property
    def POST_FILES(self):
        return self._ENDPOINT_POST_FILES

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, headers:dict):
        self._headers = headers

    @property
    def sleep_time(self):
        return self._sleep_time

    @sleep_time.setter
    def sleep_time(self, sleep_time):
        self._sleep_time = sleep_time

    @property
    def max_attempts(self):
        return self._max_attempts

    @max_attempts.setter
    def max_attempts(self, max_attempts):
        self._max_attempts = max_attempts
    
    @property
    def logger(self):
        return self._logger

    @logger.setter
    def logger(self, logger):
        self._logger = logger

    @staticmethod
    def map_endpoint(endpoint, map_dict:dict):
        return endpoint.format_map(map_dict)

    def pause(self, sleep_time):
        self._logger.info(f"[{'SLEEP':<9}] {sleep_time} seconds")
        time.sleep(sleep_time)

    def get_files(self, id):
        self._logger.info(f"[{'PROC':<9}] GET FILE REPORT")
        return self.reget(self.GET_FILES.format_map({"id":id}))
    
    def get_upload_url(self):
        self._logger.info(f"[{'PROC':<9}] GET URL FOR UPLOADING LARGE FILE")
        return self.reget(self.GET_UPLOAD_URL)

    def get_analysis(self, id):
        self._logger.info(f"[{'PROC':<9}] GET ANALYSIS STATUS")
        return self.reget(self.GET_ANALYSES.format_map({"id":id}))
    
    def post_files(self, endpoint, files):
        self._logger.info(f"[{'PROC':<9}] POST FILE")
        return self.repost(endpoint, files=files)

    def upload_files(self, file_path):
        try:
            with open(file_path, "rb") as rfp:
                data = rfp.read()
            files = dict(file=(os.path.basename(file_path), data))
            file_size = os.path.getsize(file_path)
        except FileNotFoundError:
            self._logger.error(f"FileNotFoundError:{file_path}")
            raise
        except OSError:
            self._logger.error(f"OSError:{file_path}")
            raise

        # The actual size limit is 650MBs
        if(file_size > 681574400):
            json_text = r'''{
                "error": {
                    "message": "Your client issued a request that was too large",
                    "code": "RequestEntityTooLarge"
                },
                "temp_data": {
                    "status_code": 413,
                    "status_message": "RequestEntityTooLarge",
                    "url": null
                }
            }'''
            response_dict = json.loads(json_text, object_hook=self.DotDict)
            self._logger.warning(f"[{'SIZE_LMT':<9}] TooLarge,{file_size} byte")
        elif(file_size > 33554432):
            response_dict = self.get_upload_url()
            if(response_dict.temp_data.status_code == 200):
                self.pause(self._sleep_time)
                response_dict = self.post_files(response_dict.data, files=files)
            else:
                pass
        else:
            response_dict = self.post_files(self.POST_FILES, files=files)
            
        return response_dict

    def check_analysis_status(self, id):
        """Returns the analysis status
        :return analysis_status: The value can be one of "completed", "queued", or "failed".
        """
        analysis_status = "queued"

        for i in range(1, self._max_attempts + 1):
            response_dict = self.get_analysis(id)
            if(response_dict.temp_data.status_code == 200):
                analysis_status = response_dict.data.attributes.status
            else:
                analysis_status = "failed"

            self._logger.log(
                self.getSeverity(analysis_status),
                f"[{'ANLYS_STA':<9}] {analysis_status}"
            )

            if(analysis_status == "completed" or i >= self._max_attempts):
                break

            self.pause(self._SLEEPING_TIME_FOR_ANALYSIS)
        return analysis_status
    
    def reget(self, endpoint):
        for i in range(1, self._max_attempts + 1):
            self._logger.info(f"[REQ{i:>02}>>>>] {endpoint}")

            try:
                response = None
                response = requests.get(
                    url=endpoint, headers=self._headers, timeout=(18.0, 21.5)
                )
            except:
                # https://github.com/psf/requests/blob/main/requests/exceptions.py
                pass

            response_dict = self.convert_response_to_dict(response)

            msg = str(response_dict.temp_data.status_code)
            msg += "," + response_dict.temp_data.status_message
            msg += "(Reached the max attempt count)" if(i >= self._max_attempts) else ""
            self._logger.log(
                self.getSeverity(response_dict.temp_data.status_code),
                f"[RES{i:>02}<<<<] {msg}"
            )

            is_continue = self.check_http_status_code(response_dict)
            if(not is_continue or i >= self._max_attempts):
                break

            self.pause(self._sleep_time)

        return response_dict

    def repost(self, endpoint, files=None, json=None):
        for i in range(1, self._max_attempts + 1):
            self._logger.info(f"[REQ{i:>02}>>>>] {endpoint}")

            try:
                response = None
                response = requests.post(
                    url=endpoint,
                    headers=self._headers,
                    files=files,
                    json=json,
                    timeout=(300.0, 310.0)
                )
            except:
                # https://github.com/psf/requests/blob/main/requests/exceptions.py
                pass
        
            response_dict = self.convert_response_to_dict(response)

            msg = str(response_dict.temp_data.status_code)
            msg += "," + response_dict.temp_data.status_message
            msg += "(Reached the max attempt count)" if(i >= self._max_attempts) else ""
            self._logger.log(
                self.getSeverity(response_dict.temp_data.status_code),
                f"[RES{i:>02}<<<<] {msg}"
            )

            is_continue = self.check_http_status_code(response_dict)
            if(not is_continue or i >= self._max_attempts):
                break

            self.pause(self._sleep_time)

        return response_dict

    class DotDict(dict):
        """Accessing dict with dot notation
        reference:https://blog.bitmeister.jp/?p=4658
        reference:https://stackoverflow.com/questions/2352181/
                  how-to-use-a-dot-to-access-members-of-dictionary
        """
        def __init__(self, *args, **kwargs): 
            super().__init__(*args, **kwargs) 
            self.__dict__ = self
    
        def __getattr__(self, key):
            return self.get(key, None)

    def convert_response_to_dict(self, response):
        """Convert to dictionary (JSON) format and add status code, etc
        Receive response from requests and convert the content of response to dict type.
        """
        if(response is None):
            # Add dummy dictionary if response is None
            # JSONDecoder:Convert null to None in decoding by default
            json_text = r'''{
                "error":{
                    "message": "The requests module raised an exception.",
                    "code": "NetworkConnectionError"
                },
                "temp_data":{
                    "status_code": "None",
                    "status_message": "NetworkConnectionError",
                    "url": null
                }
            }'''
            json_dict = json.loads(json_text, object_hook=self.DotDict)
        elif(response.status_code == 200):
            json_text = json.dumps(response.json())
            json_dict = json.loads(json_text, object_hook=self.DotDict)
            json_dict.update({
                "temp_data": self.DotDict({
                    "status_code": response.status_code,
                    "status_message": "succeeded",
                    "url": response.url
                })
            })
        else:
            try:
                json_text = json.dumps(response.json())
                json_dict = json.loads(json_text, object_hook=self.DotDict)
                json_dict.update({
                    "temp_data": self.DotDict({
                        "status_code": response.status_code,
                        "status_message": json_dict.error.code,
                        "url": response.url
                    })
                })
            except:
                # 413 Request Entity Too Large, etc
                json_dict = {
                    "error": {
                        "message": response.text,
                        "code": "RequestsJSONDecodeError"
                    },
                    "temp_data": {
                        "status_code": response.status_code,
                        "status_message": "RequestsJSONDecodeError",
                        "url": response.url
                    }
                }
                json_text = json.dumps(json_dict)
                json_dict = json.loads(json_text, object_hook=self.DotDict)
        return json_dict

    @staticmethod
    def check_http_status_code(response_dict):
        """Check for re-request necessity"""
        if(response_dict.temp_data.status_code == 0):
            is_continue = True
        elif(response_dict.temp_data.status_code == 200):
            # A successful request's response returns a 200 HTTP status code
            is_continue = False
        elif(response_dict.temp_data.status_code == 404):
            # 404 NotFoundError (No matches found)
            is_continue = False
        elif(response_dict.temp_data.status_code == 400
            or response_dict.temp_data.status_code == 401
            or response_dict.temp_data.status_code == 403
            or response_dict.temp_data.status_code == 413):
            # https://developers.virustotal.com/reference/errors"
            # 400 BadRequestError
            # 400 InvalidArgumentError
            # 400 NotAvailableYet
            # 400 UnselectiveContentQueryError
            # 400 UnsupportedContentQueryError
            # 401 AuthenticationRequiredError
            # 401 UserNotActiveError
            # 401 WrongCredentialsError
            # 403 ForbiddenError
            # 413 Request Entity Too Large
            is_continue = False
        else:
            is_continue = True

        return is_continue

    @staticmethod
    def normalize_data(response_dict):
        """Extract data for csv from response data"""
        data = dict.fromkeys([
            "status_code",
            "status_message",
            "last_analysis_status",
            "last_analysis_date",
            "first_submission_date",
            "times_submitted",
            "type_description",
            "trid",
            "magic",
            "meaningful_name",
            "reputation",
            "stats_malicious",
            "stats_undetected",
            "stats_harmless",
            "stats_suspicious",
            "stats_total",
            "detected_malicious",
            "detected_suspicious",
            "sandbox",
            "signature_product",
            "signature_verified",
            "signature_description",
            "signature_signers",
            "signature_copyright",
            "votes_harmless",
            "votes_malicious"
        ], "")

        if(response_dict.temp_data.status_code == 200):
            data["status_code"] = response_dict.temp_data.status_code
            data["status_message"] = response_dict.temp_data.status_message
            data["last_analysis_status"] = response_dict.temp_data.last_analysis_status
            if(response_dict.data.attributes.last_analysis_date is not None):
                timestamp = response_dict.data.attributes.last_analysis_date
                data["last_analysis_date"] = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            if(response_dict.data.attributes.first_submission_date is not None):
                timestamp = response_dict.data.attributes.first_submission_date
                data["first_submission_date"] = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            data["times_submitted"] = response_dict.data.attributes.times_submitted
            data["type_description"] = response_dict.data.attributes.type_description
            if(response_dict.data.attributes.trid is not None):
                for item_dict in response_dict.data.attributes.trid:
                    data["trid"] += f"[{item_dict.file_type}/{item_dict.probability}]"
            data["magic"] = response_dict.data.attributes.magic
            data["meaningful_name"] = response_dict.data.attributes.meaningful_name
            data["reputation"] = response_dict.data.attributes.reputation
            if(response_dict.data.attributes.last_analysis_stats is not None):
                data["stats_malicious"] = response_dict.data.attributes.last_analysis_stats.malicious
                data["stats_undetected"] = response_dict.data.attributes.last_analysis_stats.undetected
                data["stats_harmless"] = response_dict.data.attributes.last_analysis_stats.harmless
                data["stats_suspicious"] = response_dict.data.attributes.last_analysis_stats.suspicious
                data["stats_total"] = int(data["stats_malicious"])
                data["stats_total"] += int(data["stats_undetected"])
                data["stats_total"] += int(data["stats_harmless"])
                data["stats_total"] += int(data["stats_suspicious"])
            if(response_dict.data.attributes.last_analysis_results is not None):
                for engine_name, value_dict in response_dict.data.attributes.last_analysis_results.items():
                    if(value_dict.category == "malicious"):
                        data["detected_malicious"] += f"[{value_dict.engine_name}/{value_dict.result}]"
                    elif(value_dict.category == "suspicious"):
                        data["detected_suspicious"] += f"[{value_dict.engine_name}/{value_dict.result}]"
            if(response_dict.data.attributes.sandbox_verdicts is not None):
                for sandbox_name, value_dict in response_dict.data.attributes.sandbox_verdicts.items():
                    data["sandbox"] += f"[{value_dict.sandbox_name}/{value_dict.category}]"
            if(response_dict.data.attributes.signature_info is not None):
                data["signature_product"] = response_dict.data.attributes.signature_info.product
                data["signature_verified"] = response_dict.data.attributes.signature_info.verified
                data["signature_description"] = response_dict.data.attributes.signature_info.description
                data["signature_signers"] = response_dict.data.attributes.signature_info.signers
                data["signature_copyright"] = response_dict.data.attributes.signature_info.copyright
            if(response_dict.data.attributes.total_votes is not None):
                data["votes_harmless"] = response_dict.data.attributes.total_votes.harmless
                data["votes_malicious"] = response_dict.data.attributes.total_votes.malicious
        elif(response_dict.temp_data.status_code == 404):
            data["status_code"] = response_dict.temp_data.status_code
            data["status_message"] = "NoMatchesFound"
            data["last_analysis_status"] = response_dict.temp_data.last_analysis_status
        else:
            data["status_code"] = response_dict.temp_data.status_code
            data["status_message"] = response_dict.temp_data.status_message
            data["last_analysis_status"] = response_dict.temp_data.last_analysis_status

        return data

    @staticmethod
    def getSeverity(level):
        """Returns the severity for the specified level."""
        if(level == 200 
            or level == "completed"):
            return logging.INFO
        elif(level == 404 
            or level == "queued"):
            return logging.WARNING
        else:
            return logging.ERROR


class WebScreenshot:
    """Get a full screenshot of a web page
    If the web page has completed loading, the hash value is matched
    _________________________________________________________________
    Need packages for working::
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    python -m pip install selenium
    python -m pip install webdriver_manager
    _________________________________________________________________
    Import module in Python
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    import time
    import logging
    from selenium import webdriver
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    _________________________________________________________________
    Class summary
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    Constructor
      - __init__(
            self,
            sleep_time=1,
            max_attempts=10,
            logger_name=__name__ + ".WebScreenshot"
        ):
        :param sleep_time: Wait time until next match
        :param max_attempts: Maximum number of times to repeat when matching fails
        :param logger_name: Specify private logger name for class
    Property
      - sleep_time
      - max_attempts
      - logger
    Method
      - screenshot(self, url, img_file_path):
      - get(self, url, page_width=1000, page_height=600):
      - save(self, img_path):
      - close(self):
      - getSeverity(level):
    """
    def __init__(
            self, 
            sleep_time=1,
            max_attempts=10,
            logger_name=__name__ + ".WebScreenshot"
    ):
        self._sleep_time = sleep_time
        self._max_attempts = max_attempts
        self._logger = logging.getLogger(logger_name)

        options = webdriver.ChromeOptions()
        # Chrome secret mode
        options.add_argument("--incognito")
        # Runs Chrome in headless mode
        options.add_argument("--headless")
        # Temporarily needed if running on Windows
        options.add_argument("--disable-gpu") 
        # Hide scrollbar.
        options.add_argument("--hide-scrollbars")
        # Disable extensions
        options.add_argument("--disable-extensions")
        # Sets the minimum log level
        # Suppress "[0724/144023.417:INFO:CONSOLE(1)] 
        #  "SW registration_loaded", ..." message
        options.add_argument("--log-level=3")
        # Suppress "DevTools listening on ws://127.0.0.1:..." message
        options.add_experimental_option("excludeSwitches", ["enable-logging"])
        # Start the session
        # Get driver for browser version
        # WDM(WebDriverManager) output empty line to the terminal
        # | TypeError: __init__() got an unexpected keyword argument 'print_first_line'
        # | committed on 22 May 2022:removed the "print_first_line" argument
        # | https://github.com/SergeyPirogov/webdriver_manager/commit/
        # |   bcf04561558a42b70f4e7da81b33b95857d15435#
        # | Alternative:
        # |   os.environ['WDM_PRINT_FIRST_LINE'] = 'False'
        os.environ['WDM_PRINT_FIRST_LINE'] = 'False'
        service = Service(executable_path=ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=options)
        # Implicitly wait for an element to be found
        self.driver.implicitly_wait(10)

    @property
    def sleep_time(self):
        return self._sleep_time

    @sleep_time.setter
    def sleep_time(self, sleep_time):
        self._sleep_time = sleep_time

    @property
    def max_attempts(self):
        return self._max_attempts

    @max_attempts.setter
    def max_attempts(self, max_attempts):
        self._max_attempts = max_attempts

    @property
    def logger(self):
        return self._logger

    @logger.setter
    def logger(self, logger):
        self._logger = logger
    
    def screenshot(self, url, img_file_path):
        self._logger.info(f"[{'PROC':<9}] TAKE SCREENSHOT")
        status = webshot.get(url)
        if(status):
            status = webshot.save(img_file_path)
        else:
            pass
        return status

    def get(self, url, page_width=1000, page_height=600):
        status = False
        try:
            # Specify initial window size
            # Width is fixed at 1000px, height will be changed later.
            self.driver.set_window_size(page_width, page_height)
            # Load the web page
            self._logger.info(f"[{'ACCESS_PG':<9}] {url}")
            self.driver.get(url)
            # Check for changes in html element at 1 second intervals
            # If the web page has completed loading, the hash value is matched
            old_hash = "dummy1"
            new_hash = "dummy2"
            # Timeout:1s x 10
            for i in range(0, self._max_attempts):
                old_hash = new_hash
                dom = self.driver.find_element(By.TAG_NAME, "html").get_attribute("innerHTML")
                new_hash = hash(dom.encode("utf-8"))
                if(old_hash == new_hash):
                    status = True
                    break
                time.sleep(self._sleep_time)
            # Change window size height to web page size height
            # to take a screenshot of an entire webpage
            page_height = self.driver.execute_script("return document.body.scrollHeight")
            page_width = self.driver.execute_script("return document.body.scrollWidth")
            self.driver.set_window_size(page_width, page_height)
        except:
            status = False
            pass

        self._logger.log(
            self.getSeverity(status),
            f"[{'LDSTA,W,H':<9}] {status},{page_width},{page_height}"
        )

        return status

    def save(self, img_path):
        try:
            status = False
            status = self.driver.save_screenshot(img_path)
        except:
            # selenium.common.exceptions.TimeoutException:
            pass
        
        self._logger.log(
            self.getSeverity(status),
            f"[{'SVSTA,PTH':<9}] {status},{img_path}"
        )

        return status

    def close(self):
        self.driver.quit()

    @staticmethod
    def getSeverity(level):
        """Returns the severity for the specified level."""
        if(level):
            return logging.INFO
        else:
            return logging.WARNING

# Execute a script from the Command Line
if __name__ == "__main__":
    main()
