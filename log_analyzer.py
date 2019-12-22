#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import configparser
import datetime
import gzip
import json
import logging
import operator
import os
import re
import time
from collections import namedtuple, defaultdict
from string import Template

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./logs",
    "TIMESTAMP_FILE": "./log_analyzer_timestamp.txt"
}


def read_lines(log_path):
    if log_path.startswith('nginx-access-ui.log-') and log_path.endswith('.gz'):
        log = gzip.open(log_path)
    else:
        log = open(log_path)
    for line in log:
        yield line
    logging.debug("Чтение лога {}".format(log_path))
    log.close()


regex = re.compile('[0-9]{4}[0-1][0-9][0-3][0-9]')


def get_date(path):
    return datetime.datetime.strptime(re.findall(regex, path)[0], '%Y%m%d')


def get_last_logfile(dir_path):
    Last = namedtuple('Last', ["file", "date"])

    try:
        last_file = None
        last_date = None
        for file_name in os.listdir(dir_path):
            if is_file(os.path.join(dir_path, file_name)) and re.findall(regex, file_name) and not re.findall(
                    r'\S*[.]\w{2,}[.]', file_name):
                current_date = get_date(file_name)

                if last_file is None:
                    last_file = os.path.join(dir_path, file_name)
                    last_date = current_date

                if last_date < current_date:
                    last_file = os.path.join(dir_path, file_name)
                    last_date = current_date
        logging.debug("Последний файл с логами от {}".format(last_date))
        return Last(file=last_file, date=last_date)
    except Exception as error:
        logging.error(error)

        return None


def is_file(file_path):
    if file_path and os.path.isfile(file_path):
        return True


def save_string_to_file(string, f_name):
    try:
        with open(f_name, 'w') as f:
            f.write(string)
    except Exception as error:
        logging.error("Ошибка записи {}".format(error))


def update_timestamp_file(timestamp_file):
    timestamp = str(int(time.time()))
    save_string_to_file(timestamp, timestamp_file)
    return timestamp


def median(data):
    data = sorted(data)
    if len(data) % 2 == 1:
        return data[len(data) // 2]
    else:
        return 0.5 * (data[len(data) // 2 - 1] + data[len(data) // 2])


def analyze_log(log):
    logs_count = 0
    times_sum = 0
    total = 0
    urls_agg = defaultdict()
    url_list = []
    for log_line in log:
        url = time = None
        line_splits = log_line.split()
        try:
            url = line_splits[6].strip()
            time = float(line_splits[-1].strip())
        except Exception as error:
            logging.error("Неверный формат строки  {}".format(error))
        if url and time:
            urls_agg[url] = urls_agg.get(url, url_list) + [time]
            times_sum += time
            logs_count += 1
        total += 1
    print(logs_count,total)

    if float(logs_count) / total < 0.7:
        logging.error("Слишком много строк лога невалидного формата")
        raise Exception("Слишком много строк лога невалидного формата")

    data = []
    for url, times in urls_agg.items():
        data.append({
            'url': url,
            'count': len(times),
            'count_perc': round(float(len(times)) / logs_count, 3),
            'time_sum': sum(times),
            'time_perc': round(sum(times) / times_sum, 3),
            'time_avg': round(sum(times) / len(times), 3),
            'time_max': max(times),
            'time_med': median(times)

        })

    data.sort(key=operator.itemgetter('time_avg'), reverse=True)
    return data


def render_data(data):
    try:
        with open('./report.html', 'r') as fp:
            template = fp.read()
    except Exception as error:
        print(error)
    return Template(template).safe_substitute(table_json=json.dumps(data))


def report_data(report_data, report_file):

    save_string_to_file(render_data(report_data), report_file)


def parse_config(config_path):
    conf = configparser.RawConfigParser(allow_no_value=True)
    conf.read(config_path)
    return dict((name.upper(), value) for (name, value) in conf.items('default'))


def main(config):
    last = get_last_logfile(config['LOG_DIR'])
    if last.file:
        report_dir=config['REPORT_DIR']
        if not os.path.exists(report_dir):
            os.mkdir(report_dir)
        report_file = os.path.join(report_dir, 'report-{}.html'.format(last.date.strftime("%Y.%m.%d")))

        if not os.path.exists(report_file):
            data = analyze_log(read_lines(last.file))
            if data:
                report_data(data[:int(config['REPORT_SIZE'])], report_file)
                logging.info('Отчет по логам {}'.format(report_file))
        else:
            logging.info('Логи уже учтены в отчете {}'.format(report_file))
        update_timestamp_file(config['TIMESTAMP_FILE'])
    else:
        logging.error("Файла с логами не существует")
        raise Exception("Файла с логами не существует")


def read_logfile(name):
    try:
        with open(name, 'r') as f:
            logs = f.readlines()
    except Exception as error:
        logging.error(error)
        logs = []
    return logs


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='./log_analyzer.conf')
    args = parser.parse_args()

    if os.path.isfile(args.config):
        config.update(parse_config(args.config))

        logging.basicConfig(filename=config.get('LOGGING_FILE'), format='[%(asctime)s] %(levelname).1s %(message)s',
                            level=logging.DEBUG)
        main(config)


    else:
        logging.error("Ошибка чтения {}".format(args.config))
        raise ValueError("Невозможно прочитать конфиг-файл: {}".format(args.config))
