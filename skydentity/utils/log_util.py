def build_time_logging_string(event, caller, called, start, end):
    return f"{event} {caller} << {called} -- {end-start}"