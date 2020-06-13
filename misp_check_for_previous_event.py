def misp_check_for_previous_event(misp_instance):
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
    # Search based on events folder
   #"events-2020/" + event
    if not os.path.exists("events-2020"+event):
        return false
    # Search based on report ID.
    #if isight_alert.reportId:
     #   result = misp_instance.search(value=isight_alert.reportId, type_attribute='text', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
      #  if result:
       #     event = check_misp_all_results(result)

    # If no event found, search based on report URL.
    # if isight_alert.webLink and not event:
      #  result = misp_instance.search(value=isight_alert.webLink, type_attribute='link', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
      #  if result:
          #  event = check_misp_all_results(result)

   # if not result:
      #  PySilo_settings.logger.debug('Found no existing event for iSight report ID %s', isight_alert.reportId)

return false



def check_misp_all_results(a_result):
    """
    :param a_result:
    :type a_result:
    :return: previous event from MISP
    :rtype:
    """
    # PySilo_settings.logger.debug('Checking %s if it contains previous events', a_result)
    if 'message' in a_result:
        if a_result['message'] == 'No matches.':
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
