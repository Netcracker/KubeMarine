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
from pygelf import gelf, GelfTcpHandler, GelfUdpHandler, GelfTlsHandler, GelfHttpHandler

from copy import deepcopy
from typing import List, Optional

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


class EnhancedLogger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        logging.addLevelName(VERBOSE, 'VERBOSE')

    def verbose(self, msg, *args, **kwargs):
        if self.isEnabledFor(VERBOSE):
            self._log(VERBOSE, msg, args, **kwargs)


logging.setLoggerClass(EnhancedLogger)


class LogFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None, style='%', colorize=False, correct_newlines=False):
        super().__init__(fmt, datefmt, style)
        self.colorize = colorize
        self.correct_newlines = correct_newlines

    def _format(self, record):
        s = super().format(record)
        if self.colorize and record.levelname in COLORS_SCHEME:
            s = '$__COLOR_' + COLORS_SCHEME[record.levelname] + s + '$__COLOR_RESET'
        for color_name, color_code in COLORS.items():
            if self.colorize:
                s = s.replace('$__COLOR_' + color_name, color_code)
            else:
                s = s.replace('$__COLOR_' + color_name, '')
        return s

    def format(self, record):
        messages = str(record.msg).split('\n')
        if self.correct_newlines and len(messages):
            subrecord = logging.makeLogRecord(record.__dict__)
            s = ''
            for message in messages:
                if s != '':
                    s += '\n'
                subrecord.msg = message
                s += self._format(subrecord)
            return s
        else:
            return self._format(record)


class StdoutHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__(sys.stdout)

    def emit(self, record):
        if hasattr(record, 'ignore_stdout') and getattr(record, 'ignore_stdout'):
            return
        super().emit(record)
        # TODO: if output stuck, then add here self.flush()
        # More about, see at https://stackoverflow.com/questions/16633911


class FileHandlerWithHeader(logging.FileHandler):
    def __init__(self, filename, header=None, mode='a', encoding=None, delay=0):
        # Store the header information.
        self.header = header

        # Determine if the file pre-exists
        self.file_pre_exists = os.path.exists(filename)

        # Call the parent __init__
        logging.FileHandler.__init__(self, filename, mode, encoding, delay)

        # Write the header if delay is False and a file stream was created.
        if not delay and header and self.stream is not None:
            self.stream.write('%s\n' % header)

    def emit(self, record):
        # Create the file stream if not already created.
        if self.stream is None:
            self.stream = self._open()

            # If the file pre_exists, it should already have a header.
            # Else write the header to the file so that it is the first line.
            if not self.file_pre_exists:
                self.stream.write('')
                if self.header:
                    self.stream.write('%s\n' % self.header)

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
                 **kwargs):

        self._colorize = colorize
        self._correct_newlines = correct_newlines
        self._format = format
        self._datefmt = datefmt
        self._header = header

        self._formatter = LogFormatter(self._format, self._datefmt,
                                       colorize=self._colorize,
                                       correct_newlines=self._correct_newlines)

        if target.lower() == 'stdout':
            self._target = 'stdout'
            self.handler = StdoutHandler()
        elif target.lower() == 'graylog':
            self._target = 'graylog'
            if not kwargs.get('host'):
                raise Exception('Graylog host is not defined')
            if not kwargs.get('port'):
                raise Exception(f'Graylog port is not defined for "{kwargs["host"]}"')
            if not kwargs.get('type'):
                raise Exception(f'Graylog type is not defined for "{kwargs["host"]}:{kwargs["port"]}"')
            handler_options = {
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
        else:
            self._target = target
            # Output produced by remote commands might contain characters which cannot be encoded on Windows deployer.
            # Specify explicitly utf-8 encoding which is native to the remote machines.
            self.handler = FileHandlerWithHeader(self._target, mode=filemode, header=self._header, encoding='utf-8')

        self._level = LOGGING_LEVELS_BY_NAME.get(level)
        if self._level is None:
            raise Exception(f'Failed to create logger - unknown logging level: "{level}"')
        self.handler.setLevel(self._level)

        self.handler.setFormatter(self._formatter)

    def __str__(self):
        return f'target: {self._target}, level: {LOGGING_NAMES_BY_LEVEL[self._level]}, colorize: {self._colorize}, datefmt: {self._datefmt}, format: {self._format}'

    def append_to_logger(self, logger) -> None:
        logger.addHandler(self.handler)

    def has_stdout_target(self) -> bool:
        return self._target == 'stdout'


class Log:

    def __init__(self, raw_inventory, handlers: List[LogHandler]):
        self._logger = logging.getLogger(raw_inventory.get('cluster_name', 'cluster.local'))
        self._logger.setLevel(VERBOSE)

        if self._logger.hasHandlers():
            self._logger.handlers.clear()

        for handler in handlers:
            handler.append_to_logger(self._logger)

    @property
    def logger(self) -> EnhancedLogger:
        return self._logger


def parse_log_argument(argument: str) -> LogHandler:
    """
    Parse raw CLI arguments and verify for required parameters
    :param argument: Raw CLI argument string. For example: test.log;level=verbose;colorize=true
    :return: Initialized LogHandler
    """
    parameters = {}
    argument_parts = argument.split(';')
    if not argument_parts:
        raise Exception('Defined logger do not contain parameters')
    parameters['target'] = argument_parts[0]
    for parameter in argument_parts[1:]:
        if parameter == '':
            continue
        key, value, *rest = parameter.split('=')
        if key in ['colorize', 'correct_newlines', 'debug', 'compress', 'validate']:
            value = value.lower() in ['true', '1']
        elif key in ['chunk_size', 'timeout', 'port']:
            value = int(value)
        parameters[key] = value
    if not parameters.get('level'):
        raise Exception(f'Logging level is not set for logger "{parameters["target"]}"')
    return LogHandler(**parameters)


def get_dump_debug_filepath(context: dict) -> Optional[str]:
    args = context['execution_arguments']
    if args.get('disable_dump', True):
        return None

    return os.path.join(args['dump_location'], 'debug.log')


def init_log_from_context_args(globals, context, raw_inventory) -> Log:
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
        # Globals lacks of colorize property, so calculated value for Windows is "false".
        # But it is still convenient to specify the value explicitly even for Windows for debugging purpose.
        if 'colorize' not in stdout_settings:
            stdout_settings['colorize'] = (os.name != 'nt')
        handlers.append(LogHandler(target='stdout', **stdout_settings))

    log = Log(raw_inventory, handlers)

    log.logger.verbose('Using the following loggers: \n\t%s' % "\n\t".join("- " + str(x) for x in handlers))

    return log
