"""plum.main - The action starts here.

"""

import sys
import optparse
from ConfigParser import SafeConfigParser
from cStringIO import StringIO

import pcap

from plum import packetparser, tcpcollector, store, logger, daemon, groomer


usage = "Usage: %prog [options] device_type device_or_dump_file"

# These are the basic settings that any given config files can override.
config_defaults = """
[misc]
supported_device_types: live, file, autofile

[logging]
logger_id: PLUM
dump_file: /var/log/plum.dump
level: DEBUG
format: %(asctime)s %(levelname)s %(message)s
filename: /var/log/plum.log
filemode: w
maxsize: 5000000
maxbackups: 5

[ssl]
enabled: False
ports: 443

[http]
enabled: True
ports: 80
session_keys: PHPSESSID

[tds]
enabled: True
ports: 1433

[housekeeping]
fin_wait_timeout: 60

[grooming]
normal_shelf_life: 14400
defect_shelf_life: 1209600
"""

# This is output as a minimal example for the user.
example_config = """;; Example Configuration File for PLUM
;; Edit and secure to your needs.

[db]
host: localhost
db: plum_stats
user: username
passwd: password
"""


def parse_from_device(device, device_type, cfg, log, filter=None):
    """Parse traffic from a device or file and populate the database.

    The real "main method" of PyPacket.
    """
    # Setup packet capture-er.
    capture = pcap.pcap(device)
    if filter is not None:
        capture.setfilter(filter)

    parse_packet = packetparser.PacketParser(cfg, log)

    # Initialize storage and TCP conversation collector.
    storage = store.ConversationStore(cfg, log)
    try:
        collector = tcpcollector.TCPCollector(storage.store, cfg, log)

        # Start processin' some packets.
        if device_type in ('live', 'file'):
            for pos, (time_stamp, raw_packet) in enumerate(capture):

                try:
                    packet = parse_packet(time_stamp, raw_packet, device, pos)

                    # Make sure it's a TCP packet then add it.
                    if packet.get('tcp') is not None:
                        collector.add(packet)
                        #log.info('Packets in collector: %s' 
                        #         % len(collector.conv))
                        #log.raw_pkts([packet])

                    # Show stats.
                    #log.info(capture.stats())
                    #log.info(len(collector.conv.keys()))

                except KeyboardInterrupt, ki:
                    print "Good night and good luck!"

                except Exception, ex:
                    log.exception(ex)

        elif device_type == 'autofile':
            # Parse files written in sequence (TODO?).
            print 'autofile'

    finally:
        # Close storage.
        storage.close()
        log.info(len(collector.conv.keys()))


def command():
    """Run PLUM from the command line."""
    # Get command line options.
    arg_parser = optparse.OptionParser(usage=usage)
    arg_parser.add_option('-f', '--filter', help="Pcap filter.")
    arg_parser.add_option('-d', '--daemon', 
                          action='store_true', help="Run as daemon.")
    arg_parser.add_option('-c', '--config', help="Config file.")
    arg_parser.add_option('-G', '--groom', action='store_true',
                          help="Clean the DB. (DESTRUCTIVE!!!)")
    arg_parser.add_option('-i', '--interface', help="Parse interface.")
    arg_parser.add_option('-r', '--read', help="Parse dump file.")
    arg_parser.add_option('-g', '--generate', action='store_true',
                          help="Output example config. "
                               "If given, all else is ignored.")
    arg_parser.add_option('-a', '--all', action='store_true',
                          help="Output all config options. "
                               "If given, all else is ignored.")
    (options, args) = arg_parser.parse_args()

    # TODO: Check for options that don't make sense.
    # like -g with -d or -i with -u

    if options.generate: # Print sample config.
        print example_config
        sys.exit(0)

    # Load config.
    # TODO: handle parsing errors from configs.
    cfg = SafeConfigParser()
    cfg.readfp(StringIO(config_defaults))
    configs = ['/etc/plum.cfg', 
               '/etc/plum.conf', 
               '/etc/plum.cnf', 
               '/etc/plum.ini']
    if options.config:
        configs.append(options.config)
    loaded = cfg.read(configs)
    if options.config and options.config not in loaded:
        args_parser.error('User config could not be loaded.')

    # TODO: do some validation on config (has db settings, for instance).

    if options.all:
        sio = StringIO()
        cfg.write(sio)
        sio.seek(0)
        print sio.read(),
        sys.exit(0)

    log = logger.Logger(cfg)

    # Make this a daemon if option given.
    if options.daemon:
        daemon.getevil()

    if options.groom:
        # TODO: Give the user a little feedback? 
        # Need a quiet mode? Daemon automatically quiet?
        try:
            groomer.groom(cfg, log)
        except Exception, e:
            log.error('Groom failed!!!')
            log.exception(e)

    device = None
    if options.interface:
        device = options.interface
        device_type = 'live'
    elif options.read:
        device = options.read
        device_type = 'file'

    if device is not None:
        try:
            parse_from_device(device, 
                              device_type, 
                              cfg, 
                              log, 
                              filter=options.filter)
        except KeyboardInterrupt, ki:
            print "Good night and good luck!"
        except Exception, ex:
            log.exception(ex)


if __name__ == '__main__':
    command()
