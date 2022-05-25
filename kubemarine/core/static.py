from kubemarine.core import utils

GLOBALS = utils.load_yaml(
    utils.get_resource_absolute_path('resources/configurations/globals.yaml', script_relative=True))

DEFAULTS = utils.load_yaml(
    utils.get_resource_absolute_path('resources/configurations/defaults.yaml', script_relative=True))
