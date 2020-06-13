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
            
def process_isight_indicator(a_json):
    """
    Create a PySiloAlert instance of the json and make all the mappings
    :param a_json:
    :type a_json:
    """

    try:
        # Get a MISP instance per thread
        this_misp_instance = get_misp_instance()
        print('********',this_misp_instance,'*******')

        # Without a MISP instance this does not make sense
        if this_misp_instance is False:
            raise ValueError("No MISP instance found.")
            PySilo_settings.logger.debug("No MISP Instance found: ", this_misp_instance )     
            
        # Acquire a semaphore (decrease the counter in the semaphore).
        #threading used here
        if PySilo_settings.use_threading:
            thread_limiter.acquire()
        PySilo_settings.logger.debug("max number %s current number: ", thread_limiter._initial_value, )

        # Parse the FireEye iSight report
        #isight_report_instance = PySiloReport(a_json)

        # If in DEBUG mode, write the iSight reports to a file.
       # if PySilo_settings.debug_mode:
            # Create the "reports" subdirectory for storing iSight reports, if it doesn't exist already.
            #if not os.path.exists("Silo-reports-2020"):
             #   os.makedirs("Silo-reports-2020")
            #f = open("Silo-reports-2020/" + isight_report_instance.reportId, 'a')
            # Write the iSight report into the "reports" subdirectory.
            #PySilo_settings.logger.debug('creating report report ID %s in reports/', isight_report_instance.reportId)
            #f.write(json.dumps(a_json, sort_keys=True, indent=4, separators=(',', ': ')))
            #f.close()

        # Check whether we already have an event for this reportID.
        PySilo_settings.logger.debug('Checking for existing event with report ID %s', isight_report_instance.reportId)
        event_id = misp_check_for_previous_event(this_misp_instance, isight_report_instance)

        if not event_id:
            # Create a new MISP event
            PySilo_settings.logger.debug('No event found for report ID %s -- will create a new one',
                                          isight_report_instance.reportId)
            print('***create new MISP event****')
            create_misp_event(this_misp_instance, isight_report_instance)
            ###added 5-12-2020 by dmolina
            # Create the "events" subdirectory for storing iSight reports, if it doesn't exist already.
            if not os.path.exists("events-2020"):
                os.makedirs("events-2020")
            f = open("events-2020/" + event, 'a')
            # Write the iSight report into the "reports" subdirectory.
            PySilo_settings.logger.debug('creating event report ID %s in events-2020/', event)
            f.write(json.dumps(a_json, sort_keys=True, indent=4, separators=(',', ': ')))
            f.close()                                                      
        else:
            # Add the data to the found event
            event = this_misp_instance.get_event(event_id, pythonify=True)
            update_misp_event(this_misp_instance, event, isight_report_instance)

        # Reset the iSight report instance when done.
        isight_report_instance = None

        # Release the semaphore (increase the counter in the semaphore).
        if PySilo_settings.use_threading:
            thread_limiter.release()

    except AttributeError as e_AttributeError:
        sys, traceback = error_handling(e_AttributeError, a_string="Attribute Error")
        return False
    except TypeError as e_TypeError:
        sys, traceback = error_handling(e_TypeError, a_string="Type Error:")
        return False
    except Exception as e_Exception:
        sys, traceback = error_handling(e_Exception, a_string="General Error:")
        return False
# Create a new MISP event.
def create_misp_event(misp_instance, isight_report_instance):
    # No MISP event for this iSight report ID exists yet.
    # Alas, create a new MISP event.

    # Convert the publication date of the iSight report into a datetime object.
    if isight_report_instance.publishDate:
        date = datetime.datetime.fromtimestamp(isight_report_instance.publishDate)
    else:
        # If iSight doesn't provide a date, use today's date.
        date = datetime.datetime.now(datetime.timezone.utc)

    # Create a MISP event from the FireEye iSight report with the following parameters.
    print('****create new event*****')
    event = MISPEvent()
    event.distribution = 1  # This community only
    if isight_report_instance.riskRating == 'CRITICAL' or isight_report_instance.riskRating == 'Critical':
        event.threat_level_id = 1  # High
    elif isight_report_instance.riskRating == 'HIGH' or isight_report_instance.riskRating == 'High':
        event.threat_level_id = 1  # High
    elif isight_report_instance.riskRating == 'MEDIUM' or isight_report_instance.riskRating == 'Medium':
        event.threat_level_id = 2  # Medium
    elif isight_report_instance.riskRating == 'LOW' or isight_report_instance.riskRating == 'Low':
        event.threat_level_id = 3  # Low
    else:
        event.threat_level_id = 4  # Unknown
    event.analysis = 2  # Completed
    event.info = "iSIGHT: " + isight_report_instance.title
    event.date = date

    # Push the event to the MISP server.
    my_event = misp_instance.add_event(event, pythonify=True)
    print("#######Push event to MISP server####",my_event)

           
    PySilo_settings.logger.debug('Created MISP event %s for iSight report %s', event, isight_report_instance.reportId)

    # Add default tags to the event.
    misp_instance.tag(my_event, 'Source:SILOBREAKER')
    #misp_instance.tag(my_event, 'basf:source="iSight"')
    misp_instance.tag(my_event, 'CTI feed: SILOBREAKER')
    misp_instance.tag(my_event, 'tlp:amber')
    #misp_instance.tag(my_event, 'report id', isight_report_instance.reportId)
    
                                                                     

    # Use some iSight ThreatScapes for event tagging. Reports can have multiple ThreatScapes.
    #if 'Cyber Espionage' in isight_report_instance.ThreatScape:
        # VERIS distinguishes between external, internal or partner actors. This difference is not yet implemented in
        # MISP. External would be most likely.
        #misp_instance.tag(my_event, 'veris:actor:external:motive="Espionage"')
        #misp_instance.tag(my_event, 'veris:actor:motive="Espionage"')
    #if 'Hacktivism' in isight_report_instance.ThreatScape:
        #misp_instance.tag(my_event, 'veris:actor:external:variety="Activist"')
    #if 'Critical Infrastructure' in isight_report_instance.ThreatScape:
       # misp_instance.tag(my_event, 'basf:technology="OT"')
    #if 'Cyber Physical' in isight_report_instance.ThreatScape:
        #misp_instance.tag(my_event, 'basf:technology="OT"')
    #if 'Cyber Crime' in isight_report_instance.ThreatScape:
        #misp_instance.tag(my_event, 'veris:actor:external:variety="Organized crime"')

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
