import datetime
import email.utils
import hashlib
import hmac
import json
import os
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject,PyMISP
#from pymisp import PyMISP, MISPEvent, MISPObject
import requests
import sys
import threading
import time
import urllib.parse
import urllib3

# Read the config file.
import PySilo_settings

# Import our own iSight report model.
from model.PySiloReport import PySiloReport

# Suppress insecure HTTPS request warnings.
urllib3.disable_warnings()


# Error handling function.
def error_handling(e, a_string):
    """
    :param e:
    :type e:
    :param a_string:
    :type a_string:
    :return:
    :rtype:
    """
    if hasattr(e, 'message'):
        PySilo_settings.logger.debug('%s %s', a_string, e.message)
    import traceback
    PySilo_settings.logger.debug('1 %s', e.__doc__)
    PySilo_settings.logger.debug('2 %s', sys.exc_info())
    PySilo_settings.logger.debug('3 %s', sys.exc_info()[0])
    PySilo_settings.logger.debug('4 %s', sys.exc_info()[1])
    #PySilo_settings.logger.debug('5 %s', sys.exc_info()[2], 'Sorry I mean line...',
    #                              traceback.tb_lineno(sys.exc_info()[2]))
    ex_type, ex, tb = sys.exc_info()
    PySilo_settings.logger.debug('6 %s', traceback.print_tb(tb))
    return sys, traceback



import base64
import hashlib
import hmac
import html
import json
import urllib.request
import argparse
from urllib import parse

# Process all FireEye iSight reports and convert them to MISP events.
def misp_process_isight_indicators(a_result):
    """
    :param a_result:
    :type a_result:
    """
    # Process each indicator in the JSON message
    for indicator in a_result['message']:
        Print("#####indicator#####",indicator)
        PySilo_settings.logger.debug('Processing report %s', indicator['reportId'])

        if PySilo_settings.use_threading:
            # Use threads to process the indicators
            print('***threading****')
            # First, set the maximum number of threads
            thread_limiter = threading.BoundedSemaphore(value=PySilo_settings.number_threads)
            # Define a thread
            t = threading.Thread(target=process_isight_indicator, args=(indicator,))
            # Start the thread
            t.start()
        else:
            # No threading
            print('***no threading***')
            process_isight_indicator(indicator)
################################start################################
# Command line arguments 

parser = argparse.ArgumentParser()
parser.add_argument("URL", help="the endpoint of the API, inside quotation marks")
parser.add_argument("-P", "--POST", help="perform a POST request. Data can be modified in post_data.json", action='store_true')
args = parser.parse_args()

url = parse.quote(args.URL, safe=":/?&=")

with open("../secrets.json") as f: # The secrets file has the same format as the node example.
    secrets = json.load(f)

sharedKey = secrets["SharedKey"]
apiKey = secrets["ApiKey"]

if args.POST:
    verb = "POST"
    with open('post_data.json', 'rb') as f:
        body = f.read()

    # Sign the URL
    urlSignature = verb + " " + url
    message = urlSignature.encode() + body

    hmac_sha1 = hmac.new(sharedKey.encode(), message, digestmod=hashlib.sha1)
    digest = base64.b64encode(hmac_sha1.digest())

    # Fetch the data

    final_url = url + "?apiKey=" + apiKey + "&digest=" + urllib.parse.quote(digest.decode())
    req = urllib.request.Request(final_url, data=body, headers={'Content-Type': 'application/json'})

else:
    verb = "GET"
    message = verb + " " + url

    # Sign the URL

    hmac_sha1 = hmac.new(sharedKey.encode(), message.encode(), digestmod=hashlib.sha1)
    digest = base64.b64encode(hmac_sha1.digest())

    # Fetch the data

    final_url = url + "&apiKey=" + apiKey + "&digest=" + urllib.parse.quote(digest.decode())
    req = urllib.request.Request(final_url)


# Perform the request

with urllib.request.urlopen(req) as response:
    responseJson = response.read()

# Pretty print the data

responseObject = json.loads(responseJson.decode("utf-8"))
result=json.dumps(responseObject, sort_keys=True, indent=2, separators=(',', ': '))
misp_process_isight_indicators(result)
print(json.dumps(responseObject, sort_keys=True, indent=2, separators=(',', ': ')))
