from deepmerge import Merger


def list_merger(config, path, base, nxt):
    strategy = None
    strategy_definition_position = 0
    for i, v in enumerate(nxt):
        if isinstance(v, dict) and v.get('<<') is not None:
            strategy = v.get('<<')
            strategy_definition_position = i

    if strategy is None:
        strategy = 'replace'
    else:
        # delete << key-value from array elements
        del nxt[strategy_definition_position]

    if strategy == 'merge':
        elements_after = nxt[strategy_definition_position:]
        elements_before = nxt[:strategy_definition_position]

        nxt = []
        nxt.extend(elements_before)
        nxt.extend(base)
        nxt.extend(elements_after)

    return nxt


default_merger = Merger(
    [
        (list, [list_merger]),
        (dict, ["merge"])
    ],
    ["override"],
    ["override"]
)