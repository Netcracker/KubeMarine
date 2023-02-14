#!/bin/bash

# Some dependencies either do not have universal2 wheels, or pip chooses x86_64 wheel with priority on x86_64 platform.
# When building of the binary for arm64, it is necessary to explicitly specify the target platform for 3rd-party packages.
ARM64_DEPS=(
  "--platform macosx_11_0_arm64 \
    PyYAML==6.0 \
    cffi==1.15.* \
  "
  "--platform macosx_10_12_universal2 cryptography==39.0.*"
  "--platform macosx_10_9_universal2 MarkupSafe==2.1.*"
)

X86_64_DEPS=(
  "\
    PyYAML==6.0 \
    cffi==1.15.* \
  "
  "cryptography==39.0.*"
  "MarkupSafe==2.1.*"
)

UNIVERSAL_DEPS="\
  deepmerge==1.0.* \
  fabric==2.6.* \
  jinja2==3.1.* \
  invoke==1.6.* \
  ruamel.yaml==0.17.* \
  pygelf==0.4.* \
  toml==0.10.* \
  python-dateutil==2.8.* \
  deepdiff==6.2.* \
  ordered-set==4.1.* \
  paramiko==2.9.* \
  jsonschema==4.17.* \
"

ARCH=$1

PLAT_DEPS=("${X86_64_DEPS[@]}")
if [[ $ARCH == 'arm64' ]]; then
  PLAT_DEPS=("${ARM64_DEPS[@]}")
fi

# When installing non-native 3rd-party wheels to build the binary for arm64,
# pip requires to specify --target directory.
for DEP in "${PLAT_DEPS[@]}"; do
  pip install --no-deps --target dependencies $DEP
done

# Some platform-specific packages are installed above with --no-deps omitting transitive dependencies,
# but they can still be downloaded again transitively if required by the below packages.
# Pip will try to install them and fail with:
#  "WARNING: Target directory already exists. Specify --upgrade to force replacement."
# This is good, because we do need already installed platform-specific packages.
# Still more correct way would be to explicitly list all packages including transitive and install them with --no-deps,
# but we currently not manage ALL dependencies. See pyproject.yaml.
pip install --target dependencies $UNIVERSAL_DEPS

sed -i '' "s/\(target_arch\) = None/\1 = '$ARCH'/" kubemarine.spec
sed -i '' "s/\(pathex\) = \[\]/\1 = \['.\/dependencies\/'\]/" kubemarine.spec
