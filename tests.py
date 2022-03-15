import datetime
import filecmp
import unittest
from pathlib import Path

from log_analyzer import (LogfileInfo, LogfileLineInfo, LogfileType, get_last_logfile_info,
                          get_logfile_stats, parse_logfile, parse_logfile_line,
                          render_template, report_filename_from_date, select_last_logfile)


class BaseLogAnalyzerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = {
            "REPORT_SIZE": 1000,
            "REPORT_DIR": "./testdata/reports",
            "LOG_DIR": "./testdata/log"
        }


class SelectLastLogfileTest(BaseLogAnalyzerTestCase):
    """ Tests for :func:`select_select_last_logfile` function. """

    def setUp(self) -> None:
        self.files_list = [
            "nginx-access-ui.log-20110829",
            "nginx-access-ui.log-20121209",
            "nginx-access-ui.log-20170630.gz",
            "nginx-access-ui.log-20200522.bz2",
            "sample-service.log-20190918",
        ]
        self.file_info_expected = LogfileInfo(path="nginx-access-ui.log-20170630.gz",
                                              date=datetime.date(2017, 6, 30),
                                              type=LogfileType.GZIP)

    def test(self):
        result = select_last_logfile(self.files_list)
        self.assertIsInstance(result, LogfileInfo, "get_last_logfile: wrong return type")
        self.assertEqual(self.file_info_expected, result, "get_last_logfile: wrong result value")


class GetLastLogfileTest(BaseLogAnalyzerTestCase):
    """ Tests for :func:`get_last_logfile_info` function. """

    def setUp(self):
        self.last_logfile_expected = LogfileInfo(
            path=Path(self.config["LOG_DIR"]).resolve().joinpath("nginx-access-ui.log-20190630"),
            date=datetime.date(2019, 6, 30), type=LogfileType.PLAIN)

    def test(self):
        result = get_last_logfile_info(log_dir=self.config["LOG_DIR"])
        self.assertIsInstance(result, LogfileInfo,
                              "get_last_logfile: wrong return type")
        self.assertEqual(self.last_logfile_expected, result,
                         "get_last_logfile: wrong result value")

    def test_incorrect_log_dir(self):
        # file instead of log_dir as a parameter
        with self.assertRaises(expected_exception=ValueError):
            get_last_logfile_info(log_dir=self.last_logfile_expected.path)

    def test_nothing_found(self):
        # report dir instead of log dir
        result = get_last_logfile_info(log_dir=self.config["REPORT_DIR"])
        self.assertIsNone(result)


class ParseLogfileLinesTest(BaseLogAnalyzerTestCase):
    """ Parse single logfile line by :func:`parse_parse_logfile_line` function. """

    def setUp(self) -> None:
        self.correct_line: str = '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] ' \
                                 '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" ' \
                                 '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" ' \
                                 '"-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390\n'
        self.info_expected = LogfileLineInfo(
            remote_addr='1.196.116.32', remote_user='-', http_x_real_ip='-',
            time_local='29/Jun/2017:03:50:22 +0300',
            request='GET /api/v2/banner/25019354 HTTP/1.1', URL="/api/v2/banner/25019354",
            status=200, body_bytes_sent=927, http_referer='-',
            http_user_agent='Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5',
            http_x_forwarded_for='-', http_X_REQUEST_ID='1498697422-2190034393-4708-9752759',
            http_X_RB_USER='dc7161be3', request_time=0.390,
        )
        self.wrong_line: str = '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] ' \
                               '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" ' \
                               '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5"' \
                               '"1498697422-2190034393-4708-9752759" "dc7161be3"'

    def test_parse_line_correct(self):
        info = parse_logfile_line(self.correct_line)
        self.assertIsInstance(info, LogfileLineInfo)
        self.assertEqual(info, self.info_expected)

    def test_parse_line_wrong(self):
        with self.assertRaises(expected_exception=ValueError):
            parse_logfile_line(self.wrong_line)


class CreateReportForFileTest(BaseLogAnalyzerTestCase):
    """ Integration test: from logfile to report """

    def setUp(self):
        self.logfile_to_parse = LogfileInfo(
            path=Path(self.config["LOG_DIR"]).joinpath("nginx-access-ui.log-20190630"),
            date=datetime.date(2019, 6, 30), type=LogfileType.PLAIN)

        self.report_golden = Path(self.config["REPORT_DIR"]).joinpath('report-golden.html')
        self.new_report_path = Path(self.config["REPORT_DIR"]).joinpath(report_filename_from_date(
            date=self.logfile_to_parse.date))

        # clean existing report
        if self.new_report_path.is_file():
            self.new_report_path.unlink()

    def test(self):
        table_json = [dict(stats._asdict()) for stats in
                      get_logfile_stats(logfile_info=self.logfile_to_parse,
                                        result_size=self.config["REPORT_SIZE"],
                                        logfile_parser=parse_logfile)]
        render_template(table_json=table_json, report_path=self.new_report_path)
        files_equal = filecmp.cmp(self.new_report_path, self.report_golden, shallow=False)
        self.assertTrue(files_equal, msg="report files are not equal")


if __name__ == "__main__":
    unittest.main()
