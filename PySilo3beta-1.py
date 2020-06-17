#!/usr/bin/env python

# -*- coding: utf-8 -*-

#PySilo3beta-1.py
#dmolina213
#3----3
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

#from .models import PySiloReport



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
    if hasattr(e, 'Items'):
        PySilo_settings.logger.debug('%s %s', a_string, e.Items)
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
 
def misp_check_for_previous_event(misp_instance, isight_alert):
    """
    Default: No event exists for this iSight report ID.
    :param misp_instance:
    :type misp_instance:
    :param isight_alert:
    :type isight_alert:
    :return:
        event id if an event is there
        false if no event exists yet
    :rtype:
    """
    event = False

    if misp_instance is None:
        PySilo_settings.logger.debug('No MISP instance provided')
        return False

    #Search based on report ID.
    if isight_alert.Id:
        result = misp_instance.search(value=isight_alert.Id, type_attribute='text', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
       
    if result:
            event = check_misp_all_results(result)

    # If no event found, search based on report URL.
    #if isight_alert.webLink and not event:
     #   result = misp_instance.search(value=isight_alert.webLink, type_attribute='link', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
      #  if result:
       #     event = check_misp_all_results(result)

    if not result:
        PySilo_settings.logger.debug('Found no existing event for iSight report ID %s', isight_alert.reportId)

    return event
# Update an existing MISP event.






def update_misp_event(misp_instance, event, isight_alert):

   # Update attributes based on the iSight report.
   #
   # Ideas of Alex not implemented: 
   # Use expanded networkIdentifier as a comment.

   # Create attributes and use object relationships for iSight fields that have no corresponding MISP object attribute.

   #

   # Unused iSight fields: observationTime



   PySilo_settings.logger.debug('Updating the event %s', event)
   # Verify that misp_instance is of the correct type
   #if not isinstance(misp_instance, PyMISP):
   if not isinstance(misp_instance, ExpandedPyMISP):
      PySilo_settings.logger.debug('Parameter misp_instance is not a PyMISP object')
      return False

   #silobreaker stuff added by dmolna213
   if isight_alert.Type='Email':
      default_comment=isight_alert.EntityReference
   else: 
      default_comment = ''

   # Determine whether the to_ids flag shall be set.

   if isight_alert.emailIdentifier == 'Attacker' or isight_alert.emailIdentifier == 'Compromised':

      email_ids = True

   else:

      email_ids = False

   if isight_alert.fileIdentifier == 'Attacker' or isight_alert.fileIdentifier == 'Compromised':

      file_ids = True

   elif isight_alert.intelligenceType == 'malware':

     file_ids = True

   else:

     file_ids = False

   if isight_alert.networkIdentifier == 'Attacker' or isight_alert.networkIdentifier == 'Compromised':

      network_ids = True

   else:

   network_ids = False



   # Use malwareFamily as the default comment.

   if isight_alert.malwareFamily:

      default_comment = isight_alert.malwareFamily

    else:

       default_comment = ''



    # If the alert contains email indicators, create an email object.
     if isight_alert.emailIdentifier:
        # If emailLanguage is provided, add it to the default comment.
        if isight_alert.emailLanguage:
            add_comment = 'Email language: ' + isight_alert.emailLanguage
            if default_comment == '':
                email_comment = add_comment
            else:
                email_comment = default_comment + '; ' + add_comment
        else:
            email_comment = default_comment
        # Create the object.
        email_object = MISPObject('email')
        email_object.comment = email_comment
        # Add attributes to the object.
        if isight_alert.senderAddress:
            email_object.add_attribute('from', value=isight_alert.senderAddress, to_ids=email_ids)
        if isight_alert.senderName:
            email_object.add_attribute('from-display-name', value=isight_alert.senderName, to_ids=False)
        if isight_alert.sourceIP:
            email_object.add_attribute('ip-src', value=isight_alert.sourceIP, to_ids=email_ids)
        if isight_alert.subject:
            email_object.add_attribute('subject', value=isight_alert.subject, to_ids=False)
        if isight_alert.recipient:
            email_object.add_attribute('to', value=isight_alert.recipient, to_ids=False)
        if isight_alert.senderDomain:
            domain_attribute = event.add_attribute(category='Network activity', type='domain',
                                                   value=isight_alert.senderDomain, to_ids=False)
            email_object.add_reference(domain_attribute.uuid, 'derived-from', comment='Email source domain')
        # Lastly, add the object to the event.
        event.add_object(email_object)

    # If the report contains an MD5 hash, create a file object.
    if isight_alert.md5:
        # If a file description is given, add it to the default comment.
        if isight_alert.description:
            add_comment = isight_alert.description
            if default_comment == '':
                file_comment = add_comment
            else:
                file_comment = default_comment + '; ' + add_comment
        else:
            file_comment = default_comment
        # Create the object.
        file_object = MISPObject('file')
        file_object.comment = file_comment
        # Add attributes to the object.
        file_object.add_attribute('md5', value=isight_alert.md5, to_ids=file_ids)
        if isight_alert.sha1:
            file_object.add_attribute('sha1', value=isight_alert.sha1, to_ids=file_ids)
        if isight_alert.sha256:
            file_object.add_attribute('sha256', value=isight_alert.sha256, to_ids=file_ids)
        if isight_alert.fileName and not isight_alert.fileName == 'UNAVAILABLE' and \
                not isight_alert.fileName.upper() == 'UNKNOWN':
            # Don't use filenames for detection.
            file_object.add_attribute('filename', value=isight_alert.fileName, to_ids=False)
        if isight_alert.fileSize:
            # Don't use file size for detection.
            file_object.add_attribute('size-in-bytes', value=isight_alert.fileSize, to_ids=False)
        if isight_alert.fuzzyHash:
            file_object.add_attribute('ssdeep', value=isight_alert.fuzzyHash, to_ids=file_ids)
        if isight_alert.fileType and not isight_alert.fileType == 'fileType':
            # Don't use file type for detection.
            file_object.add_attribute('text', value=isight_alert.fileType, to_ids=False)
        if isight_alert.fileCompilationDateTime:
            # Convert epoch format to ISO86011 UTC format.
            compile_date = datetime.datetime.fromtimestamp(isight_alert.fileCompilationDateTime)
            file_object.add_attribute('compilation-timestamp', value=str(compile_date), to_ids=False)
        if isight_alert.filePath:
            file_object.add_attribute('path', value=isight_alert.filePath, to_ids=False)
        # Lastly, add the object to the event.
        event.add_object(file_object)

    # If the report contains a user agent string, create a user-agent attribute.
    if isight_alert.userAgent:
        event.add_attribute(category='Network activity', type='user-agent', value=isight_alert.userAgent,
                            to_ids=network_ids, comment=default_comment)

    # If the report contains an ASN, create an AS attribute.
    if isight_alert.asn:
        # Don't use the ASN for detection.
        event.add_attribute(category='Network activity', type='AS', value=isight_alert.asn, to_ids=False,
                            comment=default_comment)

    # If the report contains a domain, create a hostname attribute (because iSight domain names are in fact hostnames).
    if isight_alert.domain:
        # If an IP address is provided with a hostname, put the IP address in a comment, possibly in addition to the
        # default network comment.
        if isight_alert.ip:
            add_comment = 'Resolves to ' + isight_alert.ip
            if default_comment == '':
                temp_comment = add_comment
            else:
                temp_comment = default_comment + '; ' + add_comment
        else:
            temp_comment = default_comment
        # If a protocol is provided, also add it to the comment.
        if isight_alert.protocol:
            add_comment = isight_alert.protocol
            if temp_comment == '':
                host_comment = add_comment
            else:
                host_comment = temp_comment + '; ' + add_comment
        else:
            host_comment = temp_comment
        # Add the attribute to the event. If a port is provided, use a combined attribute.
        if isight_alert.port:
            host_port = isight_alert.domain + '|' + isight_alert.port
            new_attr = event.add_attribute(category='Network activity', type='hostname|port', value=host_port,
                                           to_ids=network_ids, comment=host_comment)
        else:
            new_attr = event.add_attribute(category='Network activity', type='hostname', value=isight_alert.domain,
                                           to_ids=network_ids, comment=host_comment)
        if isight_alert.networkType == 'C&C':
            # Add veris tag to attribute.
            new_attr.add_tag('veris:action:malware:variety="C2"')
            new_attr.add_tag('vIsight:APIv3')
    # If the report doesn't contain a hostname but contains an IP address, create an ip-src or ip-dst attribute.
    # TODO: Is there a better way to determine whether it's a source or destination IP address?
    elif isight_alert.ip:
        # Add the protocol to the comment if it is provided by iSight.
        if isight_alert.protocol:
            add_comment = isight_alert.protocol
            if default_comment == '':
                ip_comment = add_comment
            else:
                ip_comment = default_comment + '; ' + add_comment
        else:
            ip_comment = default_comment
        if isight_alert.networkIdentifier == 'Attacker':
            # Might be source or destination, but likelihood of source is higher.
            ip_type = 'ip-src'
            if isight_alert.networkType == 'C&C':
                ip_type = 'ip-dst'
        elif isight_alert.networkIdentifier == 'Compromised':
            # Might be source or destination, but likelihood of destination is higher.
            ip_type = 'ip-dst'
        elif isight_alert.networkIdentifier == 'Related':
            # Might be source or destination, but likelihood of source is higher.
            ip_type = 'ip-src'
        elif isight_alert.networkIdentifier == 'Victim':
            # Might be source or destination, but likelihood of destination is higher.
            ip_type = 'ip-dst'
        else:
            # Might be source or destination, but likelihood of source is higher.
            ip_type = 'ip-src'
        if isight_alert.port:
            # If a port is provided, it's likely a destination IP address.
            ip_type = 'ip-dst'
            type_combo = ip_type + '|port'
            ip_port = isight_alert.ip + '|' + isight_alert.port
            new_attr = event.add_attribute(category='Network activity', type=type_combo, value=ip_port,
                                           to_ids=network_ids, comment=ip_comment)
        else:
            new_attr = event.add_attribute(category='Network activity', type=ip_type, value=isight_alert.ip,
                                           to_ids=network_ids, comment=ip_comment)
        if isight_alert.networkType == 'C&C':
            # Add veris tag to attribute.
            new_attr.add_tag('veris:action:malware:variety="C2"')

    # If the report contains a domain registrant email address, then create a whois attribute.
    if isight_alert.registrantEmail:
        whois_object = MISPObject('whois')
        whois_object.comment = default_comment
        whois_object.add_attribute('registrant-email', value=isight_alert.registrantEmail, to_ids=network_ids)
        if isight_alert.registrantName:
            whois_object.add_attribute('registrant-name', value=isight_alert.registrantName, to_ids=False)
        if isight_alert.domain:
            whois_object.add_attribute('domain', value=isight_alert.domain, to_ids=network_ids)
        elif isight_alert.sourceDomain:
            whois_object.add_attribute('domain', value=isight_alert.sourceDomain, to_ids=network_ids)
        event.add_object(whois_object)

    # If the report contains a URL, create a url attribute.
    if isight_alert.url:
        event.add_attribute(category='Network activity', type='url', value=isight_alert.url, to_ids=network_ids,
                            comment=default_comment)
        if isight_alert.networkType == 'C&C':
            # Add veris tag to attribute.
            event.add_attribute_tag('veris:action:malware:variety="C2"', isight_alert.url)

    # If the report contains registry information, create a regkey attribute.
    # Ideally, the registry field would be split into hive, key and value.
    if isight_alert.registry:
        # If a file description is given, add it to the default comment.
        if isight_alert.description:
            add_comment = isight_alert.description
            if default_comment == '':
                reg_comment = add_comment
            else:
                reg_comment = default_comment + '; ' + add_comment
        else:
            reg_comment = default_comment
        event.add_attribute(category='Artifacts dropped', type='regkey', value=isight_alert.registry, to_ids=file_ids,
                            comment=reg_comment)

    # If the report contains a malware family, create a malware-type attribute.
    if isight_alert.malwareFamily:
        event.add_attribute(category='Antivirus detection', type='text', value=isight_alert.malwareFamily,
                            to_ids=False)

    # If the report contains an actor, create a threat-actor attribute.
    if isight_alert.actor:
        # Don't use the threat actor for detection.
        event.add_attribute(category='Attribution', type='threat-actor', value=isight_alert.actor, to_ids=False)

    # Finally, commit the event additions to the MISP instance.
    misp_instance.update_event(event)

    # Lastly, publish the event without sending an alert email.
    # This command expects the event ID instead of a MISPevent as argument.
    print('#####publishing event:', event['id'])
    PySilo_settings.logger.debug('#####publishing event: %s', event['id'],isight_alert.ID) 
    event.attribute.add_tag('ISIGHT APIv3')                                                
    #misp_instance.publish(event['id'], alert=False)

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

           
    PySilo_settings.logger.debug('Created MISP event %s for iSight report %s', event, isight_report_instance.Id)

    # Add default tags to the event.
    misp_instance.tag(my_event, 'Source:SILOBREAKER')
    #misp_instance.tag(my_event, 'basf:source="iSight"')
    misp_instance.tag(my_event, 'CTI feed: SILOBREAKER')
    misp_instance.tag(my_event, 'tlp:amber')
    misp_instance.tag(my_event, 'report id', isight_report_instance.Id)
    
                                                                     

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

   
    update_misp_event(misp_instance, my_event, isight_report_instance)

def check_misp_all_results(a_result):
    """
    :param a_result:
    :type a_result:
    :return: previous event from MISP
    :rtype:
    """
    # PySilo_settings.logger.debug('Checking %s if it contains previous events', a_result)
    if 'message' in a_result:
        if a_result['Items'] == 'No matches.':
            PySilo_settings.logger.debug('No existing MISP event found')
            # has really no event
            return False
    elif 'Event' in a_result[0]:
        previous_event = a_result[0]['Event']['id']
        print('#####previous event#######:',previous_event,'e[][]',event['Event']['id'])                                                             
        PySilo_settings.logger.debug('Found an existing MISP event with ID %s', previous_event)
        return previous_event
    else:
        for e in a_result['response']:
            previous_event = e['Event']['id']
            PySilo_settings.logger.debug('Found an existing MISP event with ID %s', previous_event)
            return previous_event





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
        isight_report_instance = PySiloReport(a_json)

       # If in DEBUG mode, write the iSight reports to a file.
        if PySilo_settings.debug_mode:
            # Create the "reports" subdirectory for storing iSight reports, if it doesn't exist already.
            if not os.path.exists("Silo-reports-2020"):
                os.makedirs("Silo-reports-2020")
            f = open("Silo-reports-2020/" + isight_report_instance.Id, 'a')
            # Write the iSight report into the "reports" subdirectory.
            PySilo_settings.logger.debug('creating report report ID %s in reports/', isight_report_instance.Id)
            f.write(json.dumps(a_json, sort_keys=True, indent=4, separators=(',', ': ')))
            f.close()

        # Check whether we already have an event for this reportID.
        PySilo_settings.logger.debug('Checking for existing event with report ID %s', isight_report_instance.Id)
        event_id = misp_check_for_previous_event(this_misp_instance, isight_report_instance)

        if not event_id:
            # Create a new MISP event
            PySilo_settings.logger.debug('No event found for report ID %s -- will create a new one')
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
            update_misp_event(this_misp_instance, event,isight_report_instance)

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
#get misp instance

def get_misp_instance():
    print('*******get misp instance()********')

    """
    :return: MISP Instance
    :rtype: PyMISP
    """
    # Proxy settings are taken from the config file and converted to a dict.
    if PySilo_settings.USE_MISP_PROXY:
        misp_proxies = {
            'http': str(PySilo_settings.proxy_address),
            'https': str(PySilo_settings.proxy_address)
        }
    else:
        misp_proxies = {}

    try:
        # URL of the MISP instance, API key and SSL certificate validation are taken from the config file.
        return ExpandedPyMISP(PySilo_settings.misp_url, PySilo_settings.misp_key, PySilo_settings.misp_verifycert,
                              proxies=misp_proxies)
        #return PyMISP(PySilo_settings.misp_url, PySilo_settings.misp_key, PySilo_settings.misp_verifycert,
        #              proxies=misp_proxies)
    except Exception:
        PySilo_settings.logger.debug('Unexpected error in MISP init: %s', sys.exc_info())
        return False
#Create a new MISP event.

#Create a new MISP event.

def create_misp_event(misp_instance,isight_report_instance):
    # No MISP event for this iSight report ID exists yet.
    # Alas, create a new MISP event.

    # Convert the publication date of the iSight report into a datetime object.
    #if isight_report_instance.publishDate:
       # date = datetime.datetime.fromtimestamp(isight_report_instance.publishDate)
    #else:
        # If iSight doesn't provide a date, use today's date.
        #date = datetime.datetime.now(datetime.timezone.utc)

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
    if 'Cyber Espionage' in isight_report_instance.ThreatScape:
        # VERIS distinguishes between external, internal or partner actors. This difference is not yet implemented in
        # MISP. External would be most likely.
        misp_instance.tag(my_event, 'veris:actor:external:motive="Espionage"')
        misp_instance.tag(my_event, 'veris:actor:motive="Espionage"')
    if 'Hacktivism' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'veris:actor:external:variety="Activist"')
    if 'Critical Infrastructure' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'basf:technology="OT"')
    if 'Cyber Physical' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'basf:technology="OT"')
    if 'Cyber Crime' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'veris:actor:external:variety="Organized crime"')



################################start################################
# Command line arguments 

parser = argparse.ArgumentParser()
parser.add_argument("URL", help="the endpoint of the API, inside quotation marks")
parser.add_argument("-P", "--POST", help="perform a POST request. Data can be modified in post_data.json", action='store_true')
args = parser.parse_args()

url = parse.quote(args.URL, safe=":/?&=")

with open("secrets.json") as f: # The secrets file has the same format as the node example.
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

