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

# Check url availability script.
# The script is for testing purpose only.
# The first argv parameter is source. The second argv parameter is the timeout.

import sys

major_version = sys.version_info.major
if major_version == 3:
    import urllib.request as urllib
    import urllib.parse as urlparse
else:
    import urllib2 as urllib  # type: ignore[import-not-found, no-redef]
    import urlparse as urlparse # type: ignore[import-not-found, no-redef]

try:
    source = sys.argv[1]
    timeout = int(sys.argv[2])
    parsed_url = urlparse.urlparse(source)
    no_auth_netloc = parsed_url.netloc.split('@')[-1]
    no_auth_url = parsed_url._replace(netloc="{}".format(no_auth_netloc)).geturl()

    password_mgr = urllib.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, no_auth_url, parsed_url.username or '', parsed_url.password or '')
    handler = urllib.HTTPBasicAuthHandler(password_mgr)
    opener = urllib.build_opener(handler)

    status_code = opener.open(no_auth_url, timeout=timeout).getcode()
    if status_code != 200:
        sys.stderr.write("Error status code: %s" % status_code)
        sys.exit(1)
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
