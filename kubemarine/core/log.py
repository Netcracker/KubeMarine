# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import sys
from abc import ABC, abstractmethod

from pygelf import gelf, GelfTcpHandler, GelfUdpHandler, GelfTlsHandler, GelfHttpHandler  # type: ignore[import-untyped]

from copy import deepcopy
from typing import Any, List, Optional, cast, Dict, Union

VERBOSE = 5
gelf.LEVELS.update({VERBOSE: 8})

DEFAULT_FORMAT = '%(asctime)s %(name)s %(levelname)s %(message)s'

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

COLORS = {
    'RESET': RESET_SEQ,
    'BOLD': BOLD_SEQ,
    'BLACK': COLOR_SEQ % (30 + BLACK),
    'RED': COLOR_SEQ % (30 + RED),
    'GREEN': COLOR_SEQ % (30 + GREEN),
    'YELLOW': COLOR_SEQ % (30 + YELLOW),
    'BLUE': COLOR_SEQ % (30 + BLUE),
    'MAGENTA': COLOR_SEQ % (30 + MAGENTA),
    'CYAN': COLOR_SEQ % (30 + CYAN),
    'WHITE': COLOR_SEQ % (30 + WHITE),
}

COLORS_SCHEME = {
    'WARNING': 'YELLOW',
    'VERBOSE': 'BLUE',
    'INFO': 'GREEN',
    'ERROR': 'RED',
    'CRITICAL': 'RED'
}

LOGGING_LEVELS_BY_NAME = {
    '5': VERBOSE,
    'verbose': VERBOSE,
    '10': logging.DEBUG,
    'debug': logging.DEBUG,
    '20': logging.INFO,
    'info': logging.INFO,
    '30': logging.WARNING,
    'warn': logging.WARNING,
    'warning': logging.WARNING,
    '40': logging.ERROR,
    'error': logging.ERROR,
    '50': logging.CRITICAL,
    'critical': logging.CRITICAL
}

LOGGING_NAMES_BY_LEVEL = {
    VERBOSE: 'verbose',
    logging.DEBUG: 'debug',
    logging.INFO: 'info',
    logging.WARNING: 'warning',
    logging.ERROR: 'error',
    logging.CRITICAL: 'critical'
}


class VerboseLogger(ABC):
    @abstractmethod
    def verbose(self, msg: object, *args: object, **kwargs: Any) -> None:
        pass


class EnhancedLogger(logging.Logger, VerboseLogger):
    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name, level)
        logging.addLevelName(VERBOSE, 'VERBOSE')

    def verbose(self, msg: object, *args: object, **kwargs: Any) -> None:
        if self.isEnabledFor(VERBOSE):
            self._log(VERBOSE, msg, args, **kwargs)

    def makeRecord(self, name: str, level: int, fn: str, lno: int, msg: object, args,  # type: ignore[no-untyped-def]
                   exc_info, func=None, extra=None,
                   sinfo=None) -> logging.LogRecord:
        record = super().makeRecord(name, level, fn, lno, msg, args, exc_info, func, extra, sinfo)
        caller = record.__dict__.get('real_caller')
        if caller is not None:
            record.__dict__.update(record.__dict__.pop('real_caller'))

        return record


class EnhancedLogRecord(logging.LogRecord):
    def getMessage(self) -> str:
        message = super().getMessage()
        prefix = self.__dict__.get('prefix')
        if prefix is not None:
            message = prefix + message
        return message


logging.setLoggerClass(EnhancedLogger)
logging.setLogRecordFactory(EnhancedLogRecord)


class LogFormatter(logging.Formatter):
    def __init__(self, fmt: str = None, datefmt: str = None,
                 colorize: bool = False, correct_newlines: bool = False):
        super().__init__(fmt, datefmt)
        self.colorize = colorize
        self.correct_newlines = correct_newlines

    def _format(self, record: logging.LogRecord) -> str:
        s = super().format(record)
        if self.colorize and record.levelname in COLORS_SCHEME:
            s = COLORS[COLORS_SCHEME[record.levelname]] + s + COLORS['RESET']
        return s

    def format(self, record: logging.LogRecord) -> str:
        if self.correct_newlines:
            messages = str(record.msg).split('\n')
            if len(messages) == 1:
                return self._format(record)
        else:
            return self._format(record)

        orig_msg = record.msg
        try:
            s = ''
            for message in messages:
                if s != '':
                    s += '\n'
                record.msg = message
                s += self._format(record)
            return s
        finally:
            record.msg = orig_msg


class StdoutHandler(logging.StreamHandler):
    def __init__(self, formatter: LogFormatter):
        super().__init__(sys.stdout)
        self.formatter: LogFormatter = formatter

    def emit(self, record: logging.LogRecord) -> None:
        if 'ignore_stdout' in record.__dict__:
            return
        super().emit(record)
        # TODO: if output stuck, then add here self.flush()
        # More about, see at https://stackoverflow.com/questions/16633911


class FileHandlerWithHeader(logging.FileHandler):
    def __init__(self, formatter: LogFormatter, filename: str, header: str = None,
                 mode: str = 'a', encoding: str = None):
        # Store the header information.
        self.header = header

        # Call the parent __init__
        logging.FileHandler.__init__(self, filename, mode, encoding)

        # Write the header if it was specified
        if header:
            self.stream.write('%s\n' % header)

        self.formatter: LogFormatter = formatter

    def emit(self, record: logging.LogRecord) -> None:
        # Call the parent class emit function.
        logging.FileHandler.emit(self, record)


class LogHandler:

    def __init__(self,
                 target: str,
                 level: str,
                 colorize: bool = False,
                 correct_newlines: bool = False,
                 filemode: str = 'a',
                 format: str = DEFAULT_FORMAT,
                 datefmt: str = None,
                 header: str = None,
                 **kwargs: Union[str, bool, int]):

        self._colorize = colorize
        self._correct_newlines = correct_newlines
        self._format = format
        self._datefmt = datefmt
        self._header = header

        self._formatter = LogFormatter(self._format, self._datefmt,
                                       colorize=self._colorize,
                                       correct_newlines=self._correct_newlines)

        self.handler: logging.Handler
        if target.lower() == 'stdout':
            self._target = 'stdout'
            self.handler = StdoutHandler(self._formatter)
        elif target.lower() == 'graylog':
            self._target = 'graylog'
            if not kwargs.get('host'):
                raise Exception('Graylog host is not defined')
            if not kwargs.get('port'):
                raise Exception(f'Graylog port is not defined for "{kwargs["host"]}"')
            if not kwargs.get('type'):
                raise Exception(f'Graylog type is not defined for "{kwargs["host"]}:{kwargs["port"]}"')
            handler_options: Dict[str, Union[str, bool, int, None]] = {
                'host': kwargs['host'],
                'port': kwargs['port'],
                '_app_name': kwargs.get('appname', 'kubemarine'),
                'debug': kwargs.get('debug', False),
                'version': kwargs.get('version', '1.1')
            }
            if kwargs['type'] == 'tcp':
                self.handler = GelfTcpHandler(**handler_options)
            elif kwargs['type'] == 'udp':
                handler_options['compress'] = kwargs.get('compress', True)
                handler_options['chunk_size'] = kwargs.get('chunk_size', 1300)
                self.handler = GelfUdpHandler(**handler_options)
            elif kwargs['type'] == 'tls':
                handler_options['validate'] = kwargs.get('validate', True)
                handler_options['ca_certs'] = kwargs.get('ca_certs')
                handler_options['certfile'] = kwargs.get('certfile')
                handler_options['keyfile'] = kwargs.get('keyfile')
                self.handler = GelfTlsHandler(**handler_options)
            elif kwargs['type'] == 'http':
                handler_options['compress'] = kwargs.get('compress', True)
                handler_options['path'] = kwargs.get('path', '/gelf')
                handler_options['timeout'] = kwargs.get('timeout', 5)
                self.handler = GelfHttpHandler(**handler_options)
            else:
                raise Exception(f'Unknown Graylog type "{kwargs["type"]}" for "{kwargs["host"]}:{kwargs["port"]}"')

            self.handler.setFormatter(self._formatter)
        else:
            self._target = target
            # Output produced by remote commands might contain characters which cannot be encoded on Windows deployer.
            # Specify explicitly utf-8 encoding which is native to the remote machines.
            self.handler = FileHandlerWithHeader(self._formatter, self._target, mode=filemode, header=self._header, encoding='utf-8')

        if level not in LOGGING_LEVELS_BY_NAME:
            raise Exception(f'Failed to create logger - unknown logging level: "{level}"')
        self._level = LOGGING_LEVELS_BY_NAME[level]
        self.handler.setLevel(self._level)

    def __str__(self) -> str:
        return f'target: {self._target}, level: {LOGGING_NAMES_BY_LEVEL[self._level]}, colorize: {self._colorize}, datefmt: {self._datefmt}, format: {self._format}'

    def append_to_logger(self, logger: EnhancedLogger) -> None:
        logger.addHandler(self.handler)

    def has_stdout_target(self) -> bool:
        return self._target == 'stdout'


class Log:

    def __init__(self, raw_inventory: dict, handlers: List[LogHandler]):
        logger = logging.getLogger(raw_inventory.get('cluster_name', 'cluster.local'))
        self._logger = cast(EnhancedLogger, logger)
        self._logger.setLevel(VERBOSE)

        if self._logger.hasHandlers():
            self._logger.handlers.clear()

        for handler in handlers:
            handler.append_to_logger(self._logger)

    @property
    def logger(self) -> EnhancedLogger:
        return self._logger


class LoggerWriter:
    def __init__(self, logger: EnhancedLogger, caller: dict, prefix: str) -> None:
        self.logger = logger
        self.caller = caller
        self.prefix = prefix
        self.buf = ""

    def write(self, message: str) -> None:
        # Both remote stderr and stdout are printed to local stdout
        sys.stdout.write(message)

        lines = message.split('\n')
        for line in lines[:-1]:
            self.buf = self.buf + line
            self._log()
        self.buf = self.buf + lines[-1]

    def flush(self, remainder: bool = False) -> None:
        if remainder and self.buf:
            self._log()

    def _log(self) -> None:
        self.logger.log(logging.DEBUG, self.buf, extra={
            'real_caller': self.caller, 'prefix': self.prefix, 'ignore_stdout': True
        })
        self.buf = ""

    def __repr__(self) -> str:
        return f"LoggerWriter{{DEBUG,stdout}} at {hex(id(self))}"


def parse_log_argument(argument: str) -> LogHandler:
    """
    Parse raw CLI arguments and verify for required parameters
    :param argument: Raw CLI argument string. For example: test.log;level=verbose;colorize=true
    :return: Initialized LogHandler
    """
    parameters: Dict[str, Any] = {}
    argument_parts = argument.split(';')
    if not argument_parts:
        raise Exception('Defined logger do not contain parameters')
    target = argument_parts[0]
    level: Optional[str] = None
    for parameter in argument_parts[1:]:
        if parameter == '':
            continue
        value: Union[str, bool, int]
        key, value, *rest = parameter.split('=')
        if key == 'level':
            level = value
        else:
            if key in ['colorize', 'correct_newlines', 'debug', 'compress', 'validate']:
                value = value.lower() in ['true', '1']
            elif key in ['chunk_size', 'timeout', 'port']:
                value = int(value)

            parameters[key] = value

    if level is None:
        raise Exception(f'Logging level is not set for logger "{target}"')
    return LogHandler(target, level, **parameters)


def get_dump_debug_filepath(context: dict) -> Optional[str]:
    args = context['execution_arguments']
    if args['disable_dump']:
        return None

    return os.path.join(args['dump_location'], 'dump', 'debug.log')


def init_log_from_context_args(globals: dict, context: dict, raw_inventory: dict) -> Log:
    """
    Create Log from raw CLI arguments in Cluster context
    :param globals: parsed globals collection
    :param context: context holding execution arguments.
    :param raw_inventory: parsed but not yet enriched inventory
    :return: Initialized Log, based on all parsed logging arguments
    """

    handlers = []
    stdout_specified = False

    args = context['execution_arguments']
    if args.get('log') is not None:
        for argument in args.get('log'):
            handler = parse_log_argument(argument[0])
            if handler.has_stdout_target():
                if stdout_specified:
                    raise Exception('Multiple stdout logs specified')
                else:
                    stdout_specified = True
            handlers.append(handler)

    debug_filepath = get_dump_debug_filepath(context)
    if debug_filepath:
        handlers.append(LogHandler(target=debug_filepath,
                                   **globals['logging']['default_targets']['dump']))

    if not stdout_specified:
        stdout_settings = deepcopy(globals['logging']['default_targets']['stdout'])
        handlers.append(LogHandler(target='stdout', **stdout_settings))

    log = Log(raw_inventory, handlers)

    log.logger.verbose('Using the following loggers: \n\t%s' % "\n\t".join("- " + str(x) for x in handlers))

    return log


def caller_info(logger: EnhancedLogger) -> Dict[str, object]:
    """
    Catches and returns invocation metadata of the method that calls caller_info()

    :param logger: EnhancedLogger
    :return: dictionary with the invocation metadata
    """
    fn, lno, func, sinfo = logger.findCaller()
    record: logging.LogRecord = logger.makeRecord("", logging.DEBUG, fn, lno, "", (), None,
                                                  func=func, extra=None, sinfo=sinfo)
    return dict(item for item in record.__dict__.items()
                if item[0] in (
                    # record's fields describing invocation origin
                    'pathname', 'filename', 'module', 'lineno', 'funcName', 'stack_info',
                    # record's fields describing initial process and thread context
                    'thread', 'threadName', 'process', 'processName'
                ))
