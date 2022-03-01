# Log Analyzer
``Log analyzer`` is a command line tool designed to parse and analyze [nginx server](http://nginx.org/en/) logs and 
generate reports that reflect request processing time statistics.

For successful parsing, log files content must conform to a certain format. The format is defined by the ``log_format`` 
configuration section of the ``ngx_http_log_module`` and should be as follows:

```
log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID"
                     "$http_X_RB_USER" '
                    '$request_time';

```
For more details please see [``ngx_http_log_module`` description](http://nginx.org/en/docs/http/ngx_http_log_module.html#log_format)

The log file names should follow the format ``nginx-access-ui.log-<YYYYmmdd>[.gz]``. Thus, log files can be both plain 
text and gzip.

## How to use
```shell
$ python log_analyzer.py [--config CONFIG]
```
where ``CONFIG`` is the path to the configuration file in JSON format. If ``CONFIG`` is not specified [config.json](config.json) 
file in the script directory will be used.

JSON config file format with default values:

```json
{
  "REPORT_SIZE": 1000,
  "REPORT_DIR": "./reports",
  "LOG_DIR": "./log"
  "LOGGING_FILENAME": "./log.txt"
}
```

If some fields in the config file are omitted, default values will be used.

``log_analyzer`` searches for the newest nginx log file in the ``LOG_DIR`` by the filename, parses it, and creates the 
HTML report in the ``REPORT_DIR`` directory. Report filename has the format ``report-<YYYY.mm.dd>.html``, where the date 
filename part corresponds to the date in the parsed log's filename. 

The created report contains per-URL stats and has the following fields:

* ``url`` - URL without a domain name;
* ``count`` - how many times the ``url`` was requested according to the log file;
* ``count_perc`` - how many times the ``url`` occurs relative to all parsed log file records (in percents);
* ``time_avg`` - average $request_time for the ``url``;
* ``time_max`` - maximum $request_time for the ``url``;
* ``time_med`` - median of all ``count`` $request_time values for the ``url``;
* ``time_sum`` - the sum of $request_time values for the ``url``;
* ``time_perc`` - ``time_sum`` value for the current ``url`` relative to the total ``time_sum`` for all URLs (in percents).

See [report example](testdata/reports/report-golden.html).

## Dependencies
python ≥ 3.7

## Running tests
To run tests use the following command:
```shell
$ python -m unittest tests.py 
```
