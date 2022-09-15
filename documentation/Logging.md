This section provides information about configuring the logging of Kubemarine.

- [Default Behavior](#default-behavior)
- [Supported Parameters](#supported-parameters)
  - [Output to Stdout](#output-to-stdout)
  - [Output to File](#output-to-file)
  - [Output to Graylog](#output-to-graylog)

# Default Behavior

By default, Kubemarine writes its logs into two locations with the following configurations:

* stdout - Debug level, colorize enabled, and correct newlines enabled.
* `dump/debug.log` - Verbose level, colorize disabled, and correct newlines enabled.

# Supported Parameters

You can customize the default behavior and specify your own logging parameters. To do this, the `--log` argument should be specified with the parameters.
It is possible to specify an unlimited number of logs - the logs are written to all places at the same time. 
For example:

```bash
kubemarine install \
--log="example.log;level=verbose;colorize=false;correct_newlines=false;filemode=a" \
--log="graylog;level=verbose;host=10.101.182.166;port=12201;type=tcp"
```

**Warning**: Enclose the arguments in quotes to avoid parsing problems.

To configure the parameters in each case is described in the following sections.

## Output to Stdout

By default, Kubemarine already writes the logs to stdout, but this can be customized with the necessary parameters.
To do this, it is required to specify the special word `stdout` in the target and then list the following supported parameters:

* level - The log output level. It determines which logs are displayed and which are not. The supported levels are: `verbose`, `debug`, `info`, `error`, and `critical`.
* colorize - A boolean parameter that adds special characters to the output that provides colors to the text.
* correct_newlines - A boolean parameter that corrects line breaks, making each new line a separate log.
* format - It specifies the format of the logs. For more information about the formatting, refer to the official logging documentation at [https://docs.python.org/3/howto/logging.html#changing-the-format-of-displayed-messages](https://docs.python.org/3/howto/logging.html#changing-the-format-of-displayed-messages). An example format of the logs is as shown below: 
`format=%(asctime)s %(name)s %(levelname)s %(message)s`
* datefmt - It specifies the format of the date in the logs. For more information about the formatting, refer to the official logging documentation at [https://docs.python.org/3/howto/logging.html#changing-the-format-of-displayed-messages](https://docs.python.org/3/howto/logging.html#changing-the-format-of-displayed-messages). An example format of the date in the logs is as shown below:
`datefmt=%I:%M:%S`

Example:

```bash
kubemarine install \
--log="stdout;level=verbose;colorize=true;correct_newlines=true;format=%(asctime)s %(name)s %(levelname)s %(message)s;datefmt=%I:%M:%S"
```

**Note**: Be careful when specifying the format and date format. Enclose the entire `log` argument, but do not enclose the `format` and `datefmt` sections. Also, do not use separators like `=` or `;` in the format, otherwise it can cause a parsing failure.

## Output to File

Kubemarine allows you to output logs to a file. For this, the following parameters are supported:

* All parameters supported in the stdout output. 
* filemode - It specifies the mode of working with the file. `w` - rewrites the file for every run, `a` - appends new content to the file for every run.

Example:

```bash
kubemarine install \
--log="example.log;level=verbose;colorize=false;correct_newlines=false;filemode=a"
```

## Output to Graylog

Kubemarine allows you to output logs to Graylog. To do this, it is required to specify the special word `graylog` in the target and then list the following supported parameters:

* level - The log output level. It determines which logs are sent to Graylog.
* host - The Graylog hostname to connect to.
* port - The Graylog port to connect to.
* type - The connection type. It can be `tcp`, `udp`, `tls`, or `http`.

Example:

```bash
kubemarine install \
--log="graylog;level=verbose;host=10.101.182.166;port=12201;type=tcp"
```
