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

    # Search based on report ID.
    #if isight_alert.reportId:
     #   result = misp_instance.search(value=isight_alert.reportId, type_attribute='text', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
      #  if result:
       #     event = check_misp_all_results(result)

    # If no event found, search based on report URL.
    if isight_alert.webLink and not event:
        result = misp_instance.search(value=isight_alert.webLink, type_attribute='link', category='External analysis')
        # If something was found in the MISP instance, then retrieve the event
        if result:
            event = check_misp_all_results(result)

    if not result:
        PySilo_settings.logger.debug('Found no existing event for iSight report ID %s', isight_alert.reportId)

    return event
