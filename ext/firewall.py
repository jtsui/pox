from pox.core import core
from pox.lib.addresses import *
from pox.lib.packet import *

# Get a logger
log = core.getLogger("fw")


class Firewall (object):
    """
    Firewall class.
    Extend this to implement some firewall functionality.
    Don't change the name or anything -- the eecore component
    expects it to be firewall.Firewall.
    """

    def __init__(self):
        """
        Constructor.
        Put your initialization code here.
        """
        log.debug("Firewall initialized.")
        self.banned_ports = open('/root/pox/ext/banned-ports.txt').read().split('\n')
        self.banned_domains = open('/root/pox/ext/banned-domains.txt').read().split('\n')

    def _handle_ConnectionIn(self, event, flow, packet):
        """
        New connection event handler.
        You can alter what happens with the connection by altering the
        action property of the event.
        """
        log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
        if flow.dstport in banned_ports:
            event.action.deny = True
            event.action.forward = False
        else:
            event.action.forward = True

        ban = False
        for domain in banned_domains:
            if domain.split('/')[0].endswith('.' + d):
                ban = True
                break
        if ban:
            event.action.forward = False
            event.action.deny = True
        else:
            event.action.forward = True

    def _handle_DeferredConnectionIn(self, event, flow, packet):
        """
        Deferred connection event handler.
        If the initial connection handler defers its decision, this
        handler will be called when the first actual payload data
        comes across the connection.
        """
        pass

    def _handle_MonitorData(self, event, packet, reverse):
        """
        Monitoring event handler.
        Called when data passes over the connection if monitoring
        has been enabled by a prior event handler.
        """
        pass
