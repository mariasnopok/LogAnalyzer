import unittest
from json import dumps

import log_analyzer as la


class LogAnalyzerTests(unittest.TestCase):

    def test_get_last_logfile(self):
        last = la.get_last_logfile('./test_data/')
        self.assertEqual(last.file, './test_data/nginx-access-ui.log-20170703.txt')

    def test_logfile_has_invalid_extention(self):
        self.assertIsNone(la.get_last_logfile("./test_data/nginx-access-ui.log-20170705.txt.bz2"))

    def test_too_much_invalid_logstrings(self):
        self.assertRaises(Exception, la.analyze_log, la.read_lines("./test_data/nginx-access-ui.log-20170701.txt"))

    def test_return_data_after_analyze(self):
        data = la.analyze_log(la.read_lines("./test_data/nginx-access-ui.log-20170630.log"))
        self.assertIsNotNone(data)

    def test_analyze_log(self):
        data = la.analyze_log(la.read_lines("./test_data/nginx-access-ui.log-20170702.txt"))
        self.assertEquals(len(data), 6)

    def test_update_timestamp_file(self):
        timestamp = la.update_timestamp_file("./test_data/log_analyzer_timestamp.txt")
        try:
            with open("./test_data/log_analyzer_timestamp.txt", 'r') as fp:
                ts = fp.read()
        except Exception as error:
            print(error)
        self.assertEquals(timestamp, ts)

    def test_report_data(self):
        report_file = './test_data/report.html'
        data = la.analyze_log(la.read_lines("./test_data/nginx-access-ui.log-20170703.txt"))
        la.report_data(data, report_file)
        try:
            with open(report_file, 'r') as f:
                report_data = f.read()
        except Exception as error:
            print(error)
        self.assertIn(dumps(data), report_data)


if __name__ == '__main__':
    unittest.main()
