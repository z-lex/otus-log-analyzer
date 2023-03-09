#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID"
#                      "$http_X_RB_USER" '
#                     '$request_time';

import argparse
import datetime
import gzip
import json
import logging
import os
import re
import string
import sys
import typing as t
from collections import defaultdict, namedtuple
from enum import Enum
from pathlib import Path
from statistics import median

config = {"REPORT_SIZE": 1000, "REPORT_DIR": "./reports", "LOG_DIR": "./log"}

TEMPLATE_PATH = Path("./template/report.html").resolve()
ERROR_THRESHOLD = 0.2

logfile_line_pattern = r"^([\S]+)\s+"  # $remote_addr
logfile_line_pattern += r"([\S]+)\s+"  # $remote_user
logfile_line_pattern += r"([\S]+)\s+"  # $http_x_real_ip
logfile_line_pattern += r"\[(.*?)\]\s+"  # $time_local
logfile_line_pattern += r"\"([A-Z]+\s+(\S+)\s+.*?)\"\s+"  # $request (url inside)
logfile_line_pattern += r"(\d{3})\s+"  # $status
logfile_line_pattern += r"(\d+)\s+"  # $body_bytes_sent
logfile_line_pattern += r"\"(.*?)\"\s+"  # $http_referer
logfile_line_pattern += r"\"(.*?)\"\s+"  # $http_user_agent
logfile_line_pattern += r"\"(.*?)\"\s+"  # $http_x_forwarded_for
logfile_line_pattern += r"\"(.*?)\"\s+"  # $http_X_REQUEST_ID
logfile_line_pattern += r"\"(.*?)\"\s+"  # $http_X_RB_USER
logfile_line_pattern += r"(\d+\.?\d*)"  # $request_time
logfile_line_patter_obj: re.Pattern = re.compile(logfile_line_pattern)


class LogfileType(Enum):
    """Possible logfile types"""

    PLAIN = ""
    GZIP = "gz"


#: Namedtuple to store logfile information
LogfileInfo = namedtuple("LogfileInfo", ["path", "date", "type"])

#: Namedtuple to store logfile line data
LogfileLineInfo = namedtuple(
    "LogfileLineInfo",
    [
        "remote_addr",
        "remote_user",
        "http_x_real_ip",
        "time_local",
        "request",
        "URL",
        "status",
        "body_bytes_sent",
        "http_referer",
        "http_user_agent",
        "http_x_forwarded_for",
        "http_X_REQUEST_ID",
        "http_X_RB_USER",
        "request_time",
    ],
)

#: Namedtuple to store URL statistics
URLStats = namedtuple(
    "URLStats",
    [
        "count",
        "time_avg",
        "time_max",
        "time_sum",
        "url",
        "time_med",
        "time_perc",
        "count_perc",
    ],
)


def get_last_logfile_info(log_dir: t.Union[str, Path]) -> t.Optional[LogfileInfo]:
    """Find the newest logfile in a directory

    :param log_dir: path to the directory with logfiles
    :returns: `LogfileInfo` instance of the logfile or None if nothing found
    """
    log_path = Path(log_dir).resolve()
    if not log_path.is_dir():
        err_msg = (
            f"get_last_logfile_info: incorrect logfile directory parameter: '{log_dir}'. "
            f"Check if this directory exists. "
        )
        logging.error(err_msg)
        raise ValueError(err_msg)

    files = [e.name for e in log_path.iterdir() if e.is_file()]
    info = select_last_logfile(files=files)
    return info._replace(path=log_path.joinpath(info.path)) if info else None


def select_last_logfile(files: t.List[str]) -> t.Optional[LogfileInfo]:
    """Select the newest logfile from the filenames list

    :param files: a list of filenames
    :returns: `LogfileInfo` instance of the logfile or None if nothing found
    """

    filename_pattern = r"^nginx-access-ui.log-(19\d\d|20\d\d)([01]\d)([0-3]\d)(\.gz|)$"
    pattern_obj = re.compile(pattern=filename_pattern)

    result = LogfileInfo(path=None, date=datetime.date.min, type=None)
    today = datetime.date.today()
    for entry in files:
        m = pattern_obj.match(entry)
        if m is None:
            continue

        try:
            cur_date = datetime.date(
                year=int(m.group(1)), month=int(m.group(2)), day=int(m.group(3))
            )
        except Exception:
            logging.exception("can't create date from %s match object", m)
            continue

        if cur_date > result.date:
            result = LogfileInfo(
                path=entry,
                date=cur_date,
                type=LogfileType.PLAIN if len(m.group(4)) == 0 else LogfileType.GZIP,
            )

            # stop searching if today's logfile is found
            if cur_date == today:
                break

    if result.path is not None:
        return result
    return None


def parse_logfile_line(line: str) -> LogfileLineInfo:
    """ Parse logfile line passed in ``line`` parameter.

    :param line: line to parse
    :return: :class:`LogfileLineInfo` instance
    :raises ValueError: if ``line`` doesn't match expected logfile line structure and can't be \
    parsed.
    """
    m = re.match(logfile_line_patter_obj, line)
    if m is None:
        raise ValueError("wrong line structure")
    info = LogfileLineInfo._make(m.group(*range(1, 15)))
    info = info._replace(
        status=int(info.status),
        body_bytes_sent=int(info.body_bytes_sent),
        request_time=float(info.request_time),
    )
    return info


def parse_logfile(
    logfile_info: LogfileInfo,
    logfile_line_parser: t.Callable[[str], LogfileLineInfo] = parse_logfile_line,
) -> t.Iterator[t.Optional[LogfileLineInfo]]:
    """ Generator that parses logfile line by line and yields :class:`LogfileLineInfo` instance
    for each parsed line or None if the current line can't be parsed.

    :param logfile_info: information that is necessary to open and read the logfile.
    :param logfile_line_parser: callable that converts plain text to the :class:`LogfileLineInfo` \
    instance.
    :returns: an iterator over :class:`LogfileLineInfo` objects.
    """
    if not os.path.isfile(logfile_info.path):
        raise ValueError(f"Incorrect logfile path: '{logfile_info.path}'")

    with open(logfile_info.path, "rb") if logfile_info.type is LogfileType.PLAIN else gzip.open(
        logfile_info.path, "r"
    ) as fd:
        for line_binary in fd:
            line = str(line_binary, encoding="utf-8")
            try:
                yield logfile_line_parser(line)
            except ValueError:
                logging.warning("can't parse line:\n'%s'", line)
                yield None


def get_logfile_stats(
    logfile_info: LogfileInfo,
    logfile_parser: t.Callable[[LogfileInfo], t.Iterator[t.Optional[LogfileLineInfo]]],
    result_size: int,
) -> t.List[URLStats]:
    """Generate stats from logfile given

    :param logfile_info: information that is necessary to open and read the logfile.
    :param logfile_parser: generator function that yields :class:`LogfileLineInfo` instances.
    :param result_size: determines how many items will be included in the result.
    :returns: list of :class:`URLStats` instances.
    """

    stats = dict()
    total_lines = 0
    err_lines = 0
    summary_time = 0.0
    req_times = defaultdict(list)

    info: LogfileLineInfo
    for info in logfile_parser(logfile_info):
        total_lines += 1
        if info is None:
            err_lines += 1
            continue
        if stats.get(info.URL) is None:
            stats[info.URL] = URLStats(
                count=1,
                time_avg=0.0,
                time_max=info.request_time,
                time_sum=info.request_time,
                url=info.URL,
                time_med=0.0,
                time_perc=0.0,
                count_perc=0.0,
            )
        else:
            stats[info.URL] = stats[info.URL]._replace(
                count=stats[info.URL].count + 1,
                time_sum=stats[info.URL].time_sum + info.request_time,
                time_max=max(stats[info.URL].time_max, info.request_time),
            )

        summary_time += info.request_time
        req_times[info.URL].append(info.request_time)

    err_perc = err_lines / total_lines
    if err_perc > ERROR_THRESHOLD:
        logging.error(
            "error threshold = %.2f exceeded, current error rate is %.2f",
            ERROR_THRESHOLD,
            err_perc,
        )
        raise RuntimeError("Parsing error threshold exceeded")

    result: t.List[URLStats] = sorted(
        list(stats.values()), key=lambda x: x.time_sum, reverse=True
    )[:result_size]
    for idx, elem in enumerate(result):
        result[idx] = elem._replace(
            count_perc=f"{t.cast(int, elem.count) / (total_lines - err_lines) * 100.0:.2f}",
            time_perc=f"{elem.time_sum / summary_time * 100.0:.2f}",
            time_avg=f"{elem.time_sum / elem.count:.3f}",
            time_med=f"{float(median(req_times[elem.url])):.3f}",
        )

    return result


def report_filename_from_date(date: datetime.date) -> str:
    return "report-{}.html".format(date.strftime("%Y.%m.%d"))


def report_already_exists(report_path: Path, date: datetime.date) -> bool:
    """Check if report is already created for this date"""
    if not report_path.is_dir():
        raise ValueError(f"Incorrect report dir: '{report_path}'")
    return report_path.joinpath(report_filename_from_date(date)).is_file()


def render_template(table_json: t.List[t.Dict], report_path: Path) -> None:
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as tf:
        s = string.Template(tf.read()).safe_substitute(table_json=table_json)
    with open(report_path, "w", encoding="utf-8") as of:
        of.write(s)


def parse_config(config_text: str) -> t.Dict:
    """Make config dict from plain text data.

    :raises JSONDecodeError: if text can't be parsed.
    """
    file_config = dict()
    if len(config_text) > 0:
        file_config = json.loads(config_text)
    return file_config


def main(config: t.Dict) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        required=False,
        default="./config.json",
        type=open,
        nargs=1,
        help="path to configuration file",
    )

    try:
        args = parser.parse_args()
        config_text = args.config.read()
        args.config.close()
        file_config = parse_config(config_text)
    except Exception:
        logging.exception("ERROR: can't parse configuration file")
        return

    config.update(**file_config)

    logging_filename = config.get("LOGGING_FILENAME")
    logging.basicConfig(
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
        filename=logging_filename,
        level="INFO",
    )

    report_path = Path(config.get("REPORT_DIR"))

    try:
        last_logfile_info = get_last_logfile_info(log_dir=config.get("LOG_DIR"))

        if last_logfile_info is None:
            logging.info("No logfiles found in '%s'. Exiting...", config.get("LOG_DIR"))
            return

        logging.info("last logfile found: %s", last_logfile_info.path)

        if report_already_exists(report_path=report_path, date=last_logfile_info.date):
            logging.info(
                "Report for '%s' has already created in '%s', there's nothing to do. "
                "Exiting...",
                last_logfile_info.path,
                report_path,
            )
            return

        table_json = [
            dict(stats._asdict())
            for stats in get_logfile_stats(
                logfile_info=last_logfile_info,
                logfile_parser=parse_logfile,
                result_size=config.get("REPORT_SIZE"),
            )
        ]

        new_report_path = report_path.joinpath(
            report_filename_from_date(date=last_logfile_info.date)
        )
        render_template(table_json=table_json, report_path=new_report_path)
    except Exception:
        logging.exception("Can't finish task")
        sys.exit(1)


if __name__ == "__main__":
    main(config)
