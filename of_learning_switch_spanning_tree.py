""" OpenFlow Exercise - Sample File
This file was created as part of the course Advanced Workshop in IP Networks
in IDC Herzliya.

This code is based on the official OpenFlow tutorial code.
"""

import pox.openflow.libopenflow_01 as of
from collections import namedtuple
import pox.lib.packet as pkt
from random import shuffle
from pox.core import core
import utils
import time


log = core.getLogger()


class Tutorial(object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_in_port = dict()

        # This binds our PacketIn event listener
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed  # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch

        self.act_like_switch(packet, packet_in)

    def send_packet(self, buffer_id, raw_data, out_port, in_port):
        """
        Sends a packet out of the specified switch port.
        If buffer_id is a valid buffer on the switch, use that. Otherwise,
        send the raw data in raw_data.
        The "in_port" is the port number that packet arrived on.  Use
        OFPP_NONE if you're generating this packet.
        """
        # We tell the switch to take the packet with id buffer_if from in_port
        # and send it to out_port
        # If the switch did not specify a buffer_id, it must have specified
        # the raw data of the packet, so in this case we tell it to send
        # the raw data
        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != of.NO_BUFFER and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def act_like_switch(self, packet, packet_in):
        """
        Implement switch-like behavior -- if destination is know, send only to the learnt port, otherwise, flood (send
        all packets to all ports besides the input port).
        """

        dpid = self.connection.dpid

        log.debug('act_like_switch: dpid={}, type={}, {}.{} -> {}'
                  .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst))

        # check if we already know this src
        known_in_port = self.mac_to_in_port.get(packet.src, None)
        if known_in_port:
            # check whether src incoming port was changed
            if known_in_port != packet_in.in_port:
                log.info('src in_port was changed: dpid={}, src={} known in_port={}, new in_port={}'
                         .format(dpid, packet.src, known_in_port, packet_in.in_port))

                self._uninstall_flows(dpid, packet, known_in_port)

                log.debug('Learning: dpid={}, {} via port {}'.format(dpid, packet.src, packet_in.in_port))
                self.mac_to_in_port[packet.src] = packet_in.in_port
        else:
            # new src.in_port - learn it
            log.debug('Learning: dpid={}, {} via port {}'.format(dpid, packet.src, packet_in.in_port))
            self.mac_to_in_port[packet.src] = packet_in.in_port

        # check if we know in which port the destination is connected to
        known_in_port = self.mac_to_in_port.get(packet.dst, None)
        if known_in_port:
            # install new rule: dst via in_port
            self._install_flow(dpid, packet, packet_in, dst_port=known_in_port)
        else:
            # we do not know in which port destination is connected if at all
            log.debug('Broadcasting dpid={}, type={}, {}.{} -> {}.{}'
            .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst, of.OFPP_FLOOD))
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)

        log.debug('act_like_switch: finished: dpid={}'.format(dpid))

    def _install_flow(self, dpid, packet, packet_in, dst_port):
        """ Installing rule in switch. Rule is from any source to specific destination and src_port via dst_port """

        log.debug('Installing flow: dpid={}, match={{ dst:{}, in_port:{} }} output via port {}'
                  .format(dpid, packet.dst, packet_in.in_port, dst_port))

        msg = of.ofp_flow_mod()
        msg.match.dl_dst = packet.dst
        msg.match.in_port = packet_in.in_port
        msg.actions.append(of.ofp_action_output(port=dst_port))

        # also send the packet...
        if packet_in.buffer_id != of.NO_BUFFER and packet_in.buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = packet_in.buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if packet_in.data:
                msg.data = packet_in.data

        self.connection.send(msg)

        log.debug('Sending: dpid={}, {}.{} -> {}.{}'.format(dpid, packet.src, packet_in.in_port, packet.dst, dst_port))

    def _uninstall_flows(self, dpid, packet, old_port):
        """ Un-installing all rules to specific destination. """

        log.debug('Un-installing flow: dpid={}, {} -> {} output via port {}'
                  .format(dpid, "ff:ff:ff:ff:ff:ff", packet.src, old_port))

        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        msg.match.dl_dst = packet.src

        self.connection.send(msg)


class LLDPSender(object):
    """ Sends out LLDP discovery packets """

    SendItem = namedtuple("LLDPSenderItem", ('dpid', 'port_num', 'packet'))

    def __init__(self, send_cycle_time=1):
        """
        Initialize an LLDP packet sender

        send_cycle_time is the time (in seconds) that this sender will take to
          send all discovery packets.  Thus, it should be the link timeout
          interval at most.
        """
        # Packets remaining to be sent in this cycle
        self._this_cycle = list()

        # Packets we've already sent in this cycle
        self._next_cycle = list()

        self._timer = None
        self._send_cycle_time = send_cycle_time

        # register for switch events
        core.listen_to_dependencies(self)

    def _handle_openflow_ConnectionUp(self, event):
        self._remove_switch(event.dpid, set_timer=False)

        ports = [(port.port_no, port.hw_addr) for port in event.ofp.ports]

        for port_num, port_addr in ports:
            self._add_port(event.dpid, port_num, port_addr, set_timer=False)

        self._set_timer()

    def _handle_openflow_ConnectionDown(self, event):
        self._remove_switch(event.dpid)

    def _handle_openflow_PortStatus(self, event):
        """ Track changes to switch ports """
        if event.added or (event.modified and event.ofp.desc.config == 0):
            self._add_port(event.dpid, event.port, event.ofp.desc.hw_addr)
        elif event.deleted or (event.modified and event.ofp.desc.config == 1):
            self._remove_port(event.dpid, event.port)

    def _remove_switch(self, dpid, set_timer=True):
        self._this_cycle = [p for p in self._this_cycle if p.dpid != dpid]
        self._next_cycle = [p for p in self._next_cycle if p.dpid != dpid]

        if set_timer:
            self._set_timer()

    def _remove_port(self, dpid, port_num, set_timer=True):
        if port_num > of.OFPP_MAX:
            return

        self._this_cycle = [p for p in self._this_cycle
                            if p.dpid != dpid or p.port_num != port_num]
        self._next_cycle = [p for p in self._next_cycle
                            if p.dpid != dpid or p.port_num != port_num]

        if set_timer:
            self._set_timer()

    def _add_port(self, dpid, port_num, port_addr, set_timer=True):
        if port_num > of.OFPP_MAX:
            return

        self._remove_port(dpid, port_num, set_timer=False)

        lldpPacket = self._create_lldp_packet(dpid, port_num, port_addr)
        self._next_cycle.append(LLDPSender.SendItem(dpid, port_num, lldpPacket))

        if set_timer:
            self._set_timer()

    def _set_timer(self):
        if self._timer:
            self._timer.stop()

        self._timer = None
        num_packets = len(self._this_cycle) + len(self._next_cycle)

        if num_packets != 0:
            self._timer = utils.Timer(self._send_cycle_time / float(num_packets),
                                      self._timer_handler, recurring=True)

    def _timer_handler(self):
        """
        Called by a timer to actually send packets.

        Picks the first packet off this cycle's list, sends it, and then puts
        it on the next-cycle list.  When this cycle's list is empty, starts
        the next cycle.
        """
        if len(self._this_cycle) == 0:
            self._this_cycle = self._next_cycle
            self._next_cycle = []
            shuffle(self._this_cycle)

        if len(self._this_cycle) > 0:
            item = self._this_cycle.pop(0)
            self._next_cycle.append(item)
            core.openflow.sendToDPID(item.dpid, item.packet)

    def _create_lldp_packet(self, dpid, port_num, port_addr):
        """ Build discovery packet """

        chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_CHASSIS, id=str(dpid))

        port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(port_num))

        ttl = pkt.ttl(ttl=1)

        lldp_packet = pkt.lldp()
        lldp_packet.tlvs.append(chassis_id)
        lldp_packet.tlvs.append(port_id)
        lldp_packet.tlvs.append(ttl)
        lldp_packet.tlvs.append(pkt.end_tlv())

        eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
        eth.src = port_addr
        eth.dst = pkt.ETHERNET.LLDP_MULTICAST
        eth.payload = lldp_packet

        po = of.ofp_packet_out(action=of.ofp_action_output(port=port_num))
        po.data = eth.pack()
        return po.pack()


EventContinue = (False, False)
EventHalt = (True, False)


class Discovery(object):
    __metaclass__ = utils.SingletonType

    LINK_TIMEOUT = 6                 # How long until we consider a link dead
    LINK_TIMEOUT_CHECK_INTERVAL = 3  # How often to check for timeouts

    Link = namedtuple("Link", ("dpid1", "port1", "dpid2", "port2"))

    def __init__(self):
        self._adjacency = dict()  # From Link to time.time() stamp
        self._sender = LLDPSender()

        # Listen with a high priority so we get PacketIns as soon as possible
        core.listen_to_dependencies(self, listen_args={'openflow': {'priority': 0xffffffff}})

        # TODO: removed for debug - need to uncomment next line
        # utils.Timer(Discovery.LINK_TIMEOUT_CHECK_INTERVAL, self._delete_expired_links, recurring=True)

    def _handle_openflow_ConnectionUp(self, event):
        """ Will be called when a switch is added. """
        log.debug('_handle_openflow_ConnectionUp-> Installing flow: route LLDP messages to controller: dpid={}, {}'
                  .format(event.dpid, str(event)))

        # Make sure we get LLDP traffic
        match = of.ofp_match(dl_type=pkt.ethernet.LLDP_TYPE, dl_dst=pkt.ETHERNET.LLDP_MULTICAST)
        msg = of.ofp_flow_mod()
        msg.priority = 65000
        msg.match = match
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))

        event.connection.send(msg)

    def _handle_openflow_ConnectionDown(self, event):
        """ Will be called when a switch goes down. """
        # Delete all links on this switch
        self._delete_links([link for link in self._adjacency if link.dpid1 == event.dpid or link.dpid2 == event.dpid])

    # def _handle_PortStatus(self, event):
    # def _handle_openflow_PortStatus(self, event):
    #     """ Will be called when a link changes. """
    #     if event.ofp.desc.config == 1:  # means that link is down
    #         # event.dpid - switch id
    #         # event.port - port number
    #         pass
    #     pass

    def _handle_openflow_PacketIn(self, event):
        """ Will be called when a packet is sent to the controller. """
        lldp_pkt = event.parsed

        # we handle only LLDP packets
        if lldp_pkt.effective_ethertype != pkt.ethernet.LLDP_TYPE or lldp_pkt.dst != pkt.ETHERNET.LLDP_MULTICAST:
            return EventContinue

        # parse LLDP packet: extract sender dpid and sender port
        lldp_p = lldp_pkt.payload
        ch_id = lldp_p.tlvs[0]
        po_id = lldp_p.tlvs[1]
        r_dpid = int(ch_id.id)
        r_port = int(po_id.id)

        log.debug('_handle_openflow_PacketIn-> got LLDP packet: type={}, dpid={}, packet: dpid={}, port={}'
                  .format(event.parsed.type, event.dpid, r_dpid, r_port))

        if (event.dpid, event.port) == (r_dpid, r_port):
            log.warning('Port received its own LLDP packet: dpid={}, port={} - ignoring'
                        .format(event.dpid, event.port))
            return EventHalt

        # add/update link time
        link = Discovery.Link(r_dpid, r_port, event.dpid, event.port)
        if link not in self._adjacency:
            self._adjacency[link] = time.time()
            log.info('link detected: {}.{} -> {}.{}'.format(link.dpid1, link.port1, link.dpid2, link.port2))
        else:
            # Just update timestamp
            self._adjacency[link] = time.time()

        # do not pass LLDP packet to switch
        return EventHalt

    def _delete_links(self, links):
        for link in links:
            del self._adjacency[link]

    def _delete_expired_links(self):
        """ Remove apparently dead links """
        now = time.time()

        expired = [link for link, timestamp in self._adjacency.iteritems() if timestamp + Discovery.LINK_TIMEOUT < now]
        if expired:
            for link in expired:
                log.debug('_delete_expired_links-> removing link due to timeout: {}.{} -> {}.{}'
                          .format(link.dpid1, link.port1, link.dpid2, link.port2))

            self._delete_links(expired)


def launch():
    """ Starts the component """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)

    core.register('discovery', Discovery())
    # TODO: removed for debug
    #core.openflow.addListenerByName("ConnectionUp", start_switch)