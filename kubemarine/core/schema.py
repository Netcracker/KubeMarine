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

import json
import pathlib
from textwrap import dedent
from typing import List, Dict, Callable, Iterable

import jsonschema
from ordered_set import OrderedSet

from kubemarine.core import utils, log, errors
from kubemarine.core.cluster import KubernetesCluster


def verify_inventory(inventory: dict, cluster: KubernetesCluster):
    _verify_inventory_by_schema(cluster, inventory, 'cluster')
    procedure = cluster.context.get("initial_procedure")
    if procedure:
        _verify_inventory_by_schema(cluster, cluster.procedure_inventory, procedure)
    return inventory


def _verify_inventory_by_schema(cluster: KubernetesCluster, inventory: dict, schema_name: str):
    for_procedure = "" if schema_name == 'cluster' else f" for procedure '{schema_name}'"

    root_schema_resource = f'resources/schemas/{schema_name}.json'
    root_schema = utils.get_internal_resource_path(root_schema_resource)
    root_schema = pathlib.Path(root_schema)
    if not root_schema.exists():
        if schema_name == 'cluster' or inventory:
            raise Exception(f"Failed to find schema to validate the inventory file{for_procedure}.")
        return

    with utils.open_internal(root_schema_resource) as f:
        schema = json.load(f)

    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)

    root_schema_uri = root_schema.as_uri()
    resolver = jsonschema.RefResolver(base_uri=root_schema_uri, referrer=schema)
    validator = validator_cls(schema, resolver=resolver)

    errs = list(validator.iter_errors(inventory))
    if not errs:
        return

    context = cluster.context
    logger = cluster.log
    # TODO remove in next release
    ignore_schema_errors = context['execution_arguments']['ignore_schema_errors']

    log_method = logger.warning if ignore_schema_errors else logger.error
    log_method(f"Inventory file{for_procedure} is failed to be validated against the schema.")

    errs = _resolve_errors(errs)
    for err in errs:
        logger.verbose("------------------------------------------")
        logger.verbose(_verbose_msg(validator, err))

    debug_filepath = log.get_dump_debug_filepath(context)
    if debug_filepath:
        detailed_msg = f"See detailed message in {debug_filepath}."
    else:
        detailed_msg = "Enable verbose logs to see details."

    version = utils.get_version()
    public_schema = f"https://raw.githubusercontent.com/Netcracker/KubeMarine/{version}/kubemarine/{root_schema_resource}"
    hint = f"Inventory file{for_procedure} has incorrect format. {detailed_msg}\n" \
           f"To validate the file manually, you can use JSON schema {root_schema_uri}\n" \
           f"or its public alternative {public_schema}\n"

    msg = _error_msg(validator, errs[0])
    if ignore_schema_errors:
        context['schema_errors_ignored'] = True
        logger.warning(msg + "\n\n" + hint)
        return
    else:
        hint += f"If you are sure that the file is correct, please contact support,\n" \
                f"and use --ignore-schema-errors to proceed (option will be removed in next release).\n"

    raise errors.FailException(msg, hint=hint)


def _resolve_errors(errs: List[jsonschema.ValidationError]):
    key = _extended_relevance()
    for error in errs:
        _unnest_errors(error)

    errs.sort(key=key, reverse=True)
    outer_sorted = []
    for error in errs:
        outer_sorted.extend(_descend_errors(error))

    return outer_sorted


def _unnest_errors(error: jsonschema.ValidationError):
    context: List[jsonschema.ValidationError] = error.context
    if not context:
        return

    errors_by_subschema: Dict[int, List[jsonschema.ValidationError]] = {}
    for child in context:
        _unnest_errors(child)
        errors_by_subschema.setdefault(child.schema_path[0], []).append(child)

    # jsonschema might show not very friendly messages for anyOf / oneOf.
    # In case of failed type or enum validation in each subschema, we can unnest the error to the higher level.
    # Note that possible remaining subschema errors will be discarded,
    # but it is acceptable for our current schemas implementation.
    subschemas_errors = list(errors_by_subschema.values())
    _unnest_type_subschema_errors(error, subschemas_errors)
    _unnest_enum_subschema_errors(error, subschemas_errors)


def _descend_errors(error: jsonschema.ValidationError) -> List[jsonschema.ValidationError]:
    context: List[jsonschema.ValidationError] = error.context
    if not context:
        return [error]

    # Here can be anyOf or oneOf with all not valid subschemas.
    # The idea is taken from jsonschema.exceptions.best_match,
    # with improved heuristic algorithm of choosing of the best subschema match.
    # 1. group errors by subschema
    # 2. find error with the max relevance in each group
    # 3. choose group with the min relevance of the error found in the previous step
    # 4. take the group instead of the parent error, sort by relevance reverse
    # 5. recurse if necessary

    errors_by_subschema: Dict[int, List[jsonschema.ValidationError]] = {}
    for child in context:
        errors_by_subschema.setdefault(child.schema_path[0], []).append(child)

    key = _extended_relevance()

    for errors in errors_by_subschema.values():
        errors.sort(key=key, reverse=True)

    smallest_subschema_errors = sorted(errors_by_subschema.values(), key=lambda errors: key(errors[0]))

    # We don't recurse if two the smallest errors have the same relevance (i.e. if min == max == all).
    # This place is a candidate of future developing of better heuristic.
    if len(smallest_subschema_errors) >= 2 and key(smallest_subschema_errors[0][0]) == key(smallest_subschema_errors[1][0]):
        return [error]

    unnested_errors = []
    for err in smallest_subschema_errors[0]:
        unnested_errors.extend(_descend_errors(err))

    return unnested_errors


def _unnest_type_subschema_errors(error: jsonschema.ValidationError, subschemas_errors: List[List[jsonschema.ValidationError]]):
    if not error.context:
        return

    expected_types = OrderedSet()
    for errs in subschemas_errors:
        for child in errs:
            if child.validator == "type" and len(child.relative_path) == 0 and list(child.schema_path)[1:] == ["type"]:
                value = child.validator_value
                expected_types.update([value] if isinstance(value, str) else value)
                break
        else:  # not found error with "type" validation failed for root instance.
            break
    else:  # not found subschema not containing the necessary error, i. e. all subschemas has necessary error
        reprs = ", ".join(repr(type) for type in expected_types)
        for child in error.context:
            child.parent = None
        error.context = []
        error.validator = "type"
        error.validator_value = list(expected_types)
        error.schema_path[-1] = "type"
        error.message = f"{error.instance!r} is not of type {reprs}"
        subschemas_errors.clear()


def _unnest_enum_subschema_errors(error: jsonschema.ValidationError, subschemas_errors: List[List[jsonschema.ValidationError]]):
    if not error.context:
        return

    expected_elems = OrderedSet()
    for errs in subschemas_errors:
        for child in errs:
            if child.validator == "enum" and len(child.relative_path) == 0 and list(child.schema_path)[1:] == ["enum"]:
                expected_elems.update(child.validator_value)
                break
        else:  # not found error with "enum" validation failed for root instance.
            break
    else:  # not found subschema not containing the necessary error, i. e. all subschemas has necessary error
        expected_elems = list(expected_elems)
        for child in error.context:
            child.parent = None
        error.context = []
        error.validator = "enum"
        error.validator_value = expected_elems
        error.schema_path[-1] = "enum"
        error.message = f"{error.instance!r} is not one of {expected_elems!r}"
        subschemas_errors.clear()


def _extended_relevance() -> Callable[[jsonschema.ValidationError], tuple]:
    # The extended relevance function is intended to improve heuristic for oneOf|anyOf,
    # when it is necessary to choose the most suitable branch.

    def relevance(error: jsonschema.ValidationError):
        relevance_value = jsonschema.exceptions.relevance(error)
        if error.parent is None:
            return relevance_value

        relevance_value = _apply_property_names_heuristic(error, relevance_value)
        relevance_value = _apply_list_merging_strong_heuristic(error, relevance_value)
        relevance_value = _apply_required_and_optional_properties_heuristic(error, relevance_value)

        return relevance_value

    return relevance


def _apply_property_names_heuristic(error: jsonschema.ValidationError, relevance_value: tuple):
    # jsonschema has type matching heuristic but it works bad for "propertyNames".
    # "propertyNames" does not introduce new path element and effectively verifies the object holding the property.
    # But an attempt to match the type happens for the "propertyNames" subschema.
    # The following heuristic resolves the simplest case of oneOf|anyOf(something, schema with "propertyNames" section)

    if len(error.relative_path) == 0 and "propertyNames" in error.schema_path:
        # "propertyNames" is validated only if the instance is "object".
        # See jsonschema._validators.propertyNames. So type is always matched.
        type_matched = True
        relevance_value = list(relevance_value)
        relevance_value[3] = not type_matched
        return tuple(relevance_value)

    return relevance_value


def _apply_list_merging_strong_heuristic(error: jsonschema.ValidationError, relevance_value: tuple):
    # Other conditions being equal, the error for list merging strategy has greater relevance,
    # because if the user specified '<<', we consider that he/she intends to use this advanced feature.

    is_list_merging = len(error.relative_path) == 0 and isinstance(error.schema, dict) \
                      and "properties" in error.schema and error.schema["properties"].keys() == {"<<"}

    return _append_relevance_element(relevance_value, is_list_merging)


def _apply_required_and_optional_properties_heuristic(error: jsonschema.ValidationError, relevance_value: tuple):
    # Resolve oneOf|anyOf(object, object) ambiguity.
    # Currently only 'registry' section has such schema.
    # The chosen priority is:
    # 1. If all required properties are present, than the error has lower relevance.
    # 2. Otherwise, calculate proportion of matched properties.

    # By default, consider all required properties are present, and no properties are matched
    coeff = [False, 0]
    if len(error.relative_path) != 0 or not isinstance(error.schema, dict) or not isinstance(error.instance, dict):
        return _append_relevance_element(relevance_value, tuple(coeff))

    coeff[0] = not all(p in error.instance for p in error.schema.get("required", []))

    if len(error.schema.get("properties", {})) > 0:
        inverse_weight = len(error.schema["properties"])
        matched = set(error.instance.keys()).intersection(set(error.schema["properties"].keys()))
        # negative coefficient because more matched properties - more suitable subschema - less relevant error
        coeff[1] = - len(matched) / inverse_weight

    return _append_relevance_element(relevance_value, tuple(coeff))


def _append_relevance_element(relevance_value: tuple, elem):
    relevance_value = list(relevance_value)
    relevance_value.append(elem)
    return tuple(relevance_value)


def _error_msg(validator: jsonschema.Draft7Validator, error: jsonschema.ValidationError):
    return dedent(
        f"""\
        {_friendly_msg(validator, error)}
        On inventory{_convert_to_indices(error.absolute_path)}
        """.rstrip()
    )


def _verbose_msg(validator: jsonschema.Draft7Validator, error: jsonschema.ValidationError):
    schema_path = _convert_to_indices(list(error.absolute_schema_path)[:-1])
    return dedent(
        f"""\
        {_friendly_msg(validator, error)}
        
        Failed validating {error.validator!r} in {schema_path}
        On inventory{_convert_to_indices(error.absolute_path)}
        """.rstrip()
    )


def _friendly_msg(validator: jsonschema.Draft7Validator, error: jsonschema.ValidationError) -> str:
    if error.validator == 'minProperties':
        return f"Number of properties is less than the minimum of {error.validator_value!r}. " \
               f"Property names: {[prop for prop in error.instance]!r}"

    if error.validator == 'maxProperties':
        return f"Number of properties is greater than the maximum of {error.validator_value!r}. " \
               f"Property names: {[prop for prop in error.instance]!r}"

    if error.validator == 'minItems':
        return f"Number of items equal to {len(error.instance)} is less than the minimum of {error.validator_value!r}"

    if error.validator == 'maxItems':
        return f"Number of items equal to {len(error.instance)} is greater than the maximum of {error.validator_value!r}"

    if error.validator == 'type':
        value = error.validator_value
        expected_types = [value] if isinstance(value, str) else value
        reprs = ", ".join(repr(type) for type in expected_types)
        try:
            for type in validator.TYPE_CHECKER._type_checkers:
                if validator.is_type(error.instance, type):
                    return f"Actual instance type is {type!r}. Expected: {reprs}."
        except (AttributeError, TypeError, jsonschema.exceptions.UnknownType):
            # In current 3rd-party version the error should not appear, but let's still fall back to default behaviour
            pass

    if error.validator == 'not' and isinstance(error.validator_value, dict) \
            and error.validator_value.get('enum', {}) == ['<<'] and "propertyNames" in error.schema_path:
        return "Property name '<<' is unexpected"

    if error.validator == 'enum':
        if "propertyNames" not in error.schema_path:
            return f"Value should be one of {error.validator_value!r}"
        else:
            return f"Property name {error.instance!r} is not one of {error.validator_value!r}"

    return error.message


def _convert_to_indices(path: Iterable[str]):
    if not path:
        return ""
    return f"[{']['.join(repr(p) for p in path)}]"
