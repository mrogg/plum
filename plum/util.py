"""This file should probably not exist. Things should probably not
need to be used in 2 layers in the first place."""

def pdu_time(packet_position, borders, timeline, default=None):
    """Find the time for the given unit, borders and timeline."""
    time = timeline.get(packet_position)
    if time is None: # pipelining
        time_borders = timeline.keys()
        time_borders.sort()
        less = [b for b in time_borders if b < packet_position]
        if less:
            return timeline[less[-1]]
        else:
            return default
    else:
        return time
