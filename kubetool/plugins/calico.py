def enrich_inventory(inventory, cluster):

    # By default we use calico, but have to find it out
    # First of all we have to check is Calicon set to be installed or not
    # By default installation parameter is unset, means user did not made any decision
    if inventory["plugins"]["calico"].get("install") is None:
        # Is user defined Flannel plugin and set it to install?
        flannel_required = inventory["plugins"].get("flannel", {}).get("install", False)
        # Is user defined Canal plugin and set it to install?
        canal_required = inventory["plugins"].get("canal", {}).get("install", False)
        # If Flannel and Canal is unset or not required to install, then install Calico
        if not flannel_required and not canal_required:
            inventory["plugins"]["calico"]["install"] = True

    return inventory
