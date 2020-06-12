#!/usr/bin/env python
# -*- coding: utf-8 -*-
#PySilo3.py
"""
Created on Sep 20, 2016
Modified: May 12, 2020
Modified : May20,2020 Incorporating Isighe Apiv3
@author: deralexxx
Script to pull iocs from iSight and push them to MISP
Modified by: Douglas Molina
Alexander Jaeger
See CHANGELOG.md for history
"""

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


# This function is not used!
def misp_delete_events(a_start, a_end, a_misp_instance):
    """
    :param a_start:
    :type a_start:
    :param a_end:
    :type a_end:
    :param a_misp_instance:
    :type a_misp_instance:
    :return:
    :rtype:
    """
    print(a_start)
    print(a_end)

    try:
        for i in range(a_start, a_end, 1):
            print(i)
            a_misp_instance.delete_event(i)
        return True
    except TypeError as e:
        print("TypeError error: %s", e.message)
        return False
    except Exception:
        print("Unexpected error: %s", sys.exc_info())
        return True
        
def isight_search_indicators(base_url, public_key, private_key, hours):
    # Convert hours to seconds and subtract them from the current time
    since = int(time.time()) - hours * 60 * 60

    # Limit the returned data to that published since this Epoch datetime and the present time.
    # Therefore, add the 'since' parameter as a query string.
    params = {
        'since': since
    }
    #search_query = '/view/indicators?' + urllib.parse.urlencode(params)
                                                                    
   #############################added for silobreaker############################
    verb = "GET"
    message = verb + " " + base_url

    # Sign the URL

    hmac_sha1 = hmac.new(sharedKey.encode(), message.encode(), digestmod=hashlib.sha1)
    digest = base64.b64encode(hmac_sha1.digest())

    # Fetch the data

    final_url = base_url + "&apiKey=" + apiKey + "&digest=" + urllib.parse.quote(digest.decode())
    req = urllib.request.Request(final_url)                                                           

    # Retrieve indicators and warning data since the specified date and time.
    return isight_prepare_data_request(base_url, search_query, public_key, private_key)

        
        
        
###################################################start###############################        
 if __name__ == '__main__':
    # If loglevel equals DEBUG, log the time the script ran.
    PySilo_settings.logger.debug('PySilo2MISP started at %s', datetime.datetime.now(datetime.timezone.utc))
    if PySilo_settings.debug_mode:
        # This is to log the time used to run the script
        from timeit import default_timer as timer
        start = timer()


    # Retrieve FireEye iSight indicators of the last x hours
    print('#######hello########')
    result = isight_search_indicators(PySilo_settings.isight_url, PySilo_settings.SharedKey,PySilo_settings.APIKey, PySilo_settings.isight_last_hours)
  # PySilo_settings.logger.debug("url:",PySilo_settings.isight_url,"shared key:", PPySilo_settings.SharedKey,"APIKey:",PySilo_settings.APIKey,"hrs",PySilo_settings_last_hours)
    print('####result####',result)
    PySilo_settings.logger.debug('####result####',result)
    if result is False:
        PySilo_settings.logger.debug('No informatopm available from SiloBreaker')
    else:
        misp_process_isight_indicators(result)

    PySilo_settings.logger.debug('PySilo2MISP finished at %s', datetime.datetime.now(datetime.timezone.utc))
    # If loglevel equals DEBUG, log the time the script ran.
    if PySilo_settings.debug_mode:
        end = timer()
        PySilo_settings.logger.debug('Time taken %s', end - start)
        Print('######Script Done #######')
        
