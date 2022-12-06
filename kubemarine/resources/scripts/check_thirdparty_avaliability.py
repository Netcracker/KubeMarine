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

# Simple TCP socket listener that can be run on both python 2 and 3,
# The listener accepts connections sequentially, and suppresses the received data.
# The script is for testing purpose only.
# The first argv parameter is the TCP port to listen. The second argv parameter is the ip protocol version.

import sys

major_version = sys.version_info.major
if major_version == 3:
    import urllib.request as urllib
else:
    import urllib

try:
    source = sys.argv[1]
    status_code = urllib.urlopen(source).getcode()
    if status_code != 200:
        sys.stderr.write("Error status code: %s" % status_code)
        exit(1)
except Exception as e:
    sys.stderr.write(str(e))
    exit(1)
