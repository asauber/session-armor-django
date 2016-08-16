# Grab the list of standardized headers from IANA
# Pare it down to just the standardized HTTP headers with a reference document
# Write those out as a csv

import requests
import pandas

requests.get('http://www.iana.org/assignments/message-headers/perm-headers.csv')
