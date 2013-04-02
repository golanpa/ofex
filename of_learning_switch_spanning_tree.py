""" OpenFlow Exercise - Sample File
This file was created as part of the course Advanced Workshop in IP Networks
in IDC Herzliya.

This code is based on the official OpenFlow tutorial code.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import utils


log = core.getLogger()


class HostInfo(object):
    def __init__(self, eth_addr, in_port=-1):
        self.eth_addr = eth_addr
        self.in_port = in_port
        self.rule_installed = False

    def __str__(self):
        return 'mac={}, in_port={}, installed={}'.format(self.eth_addr, self.in_port, self.rule_installed)


class Tutorial(object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_host = dict()

        # self._install_lldp_to_controller_flow()

        # This binds our PacketIn event listener
        connection.addListeners(self)

    def _install_lldp_to_controller_flow(self):
        from pox.lib.packet.ethernet import LLDP_MULTICAST
        """ Installing rule in switch. Rule is from any source to specific destination via dst_port """

        log.debug('Installing LLDP flow: dpid={}, match: type={}, dst={} output to controller via port {}'
                  .format(self.connection.dpid, pkt.ethernet.LLDP_TYPE, LLDP_MULTICAST, of.OFPP_CONTROLLER))

        msg = of.ofp_flow_mod()
        msg.match.dl_type = pkt.ethernet.LLDP_TYPE
        msg.match.dl_dst = LLDP_MULTICAST
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))

        self.connection.send(msg)

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
        Implement switch-like behavior -- if destination is know - send only to the learnt port, otherwise, send all
        packets to all ports besides the input port.
        """

        dpid = self.connection.dpid

        log.debug('act_like_switch: dpid={}, type={}, {}.{} -> {}'
                  .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst))

        # check if we already know this src
        host_info = self.mac_to_host.get(packet.src, None)
        if host_info:
            # check whether src incoming port was changed
            if host_info.in_port != packet_in.in_port:
                log.info('src in_port was changed: dpid={}, info={}, new in_port={}'
                         .format(dpid, host_info, packet_in.in_port))

                if host_info.rule_installed:
                    self._uninstall_flow(dpid, packet, host_info.in_port)
                    host_info.rule_installed = False

                log.debug('Learning: dpid={}, {} via port {}'.format(dpid, packet.src, packet_in.in_port))
                host_info.in_port = packet_in.in_port
        else:
            # new src.in_port - learn it
            log.debug('Learning: dpid={}, {} via port {}'.format(dpid, packet.src, packet_in.in_port))
            self.mac_to_host[packet.src] = HostInfo(packet.src, packet_in.in_port)

        # check if we know in which port the destination is connected to
        dst_host_info = self.mac_to_host.get(packet.dst, None)
        if dst_host_info:
            # install new rule: dst via in_port
            self._install_flow(dpid, packet, packet_in, dst_port=dst_host_info.in_port)
            dst_host_info.rule_installed = True

            # log.info('Sending: dpid={}, type={}, {}.{} -> {}.{}'
            #          .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst, dst_host_info.in_port))
            # self.send_packet(packet_in.buffer_id, packet_in.data, dst_host_info.in_port, packet_in.in_port)
        else:
            # we do not know in which port destination is connected if at all
            log.debug('Broadcasting dpid={}, type={}, {}.{} -> {}.{}'
                      .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst, of.OFPP_FLOOD))
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)

        log.debug('act_like_switch: finished: dpid={}'.format(dpid))

    def _install_flow(self, dpid, packet, packet_in, dst_port):
        """ Installing rule in switch. Rule is from any source to specific destination via dst_port """

        log.debug('Installing flow: dpid={}, match={{ dst:{}, in_port:{} }} output via port {}'
                  .format(dpid, packet.dst, packet_in.in_port, dst_port))

        msg = of.ofp_flow_mod()
        msg.match.dl_dst = packet.dst
        msg.match.in_port = packet_in.in_port
        msg.actions.append(of.ofp_action_output(port=dst_port))

        if packet_in.buffer_id != of.NO_BUFFER and packet_in.buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = packet_in.buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if packet_in.data:
                msg.data = packet_in.data

        self.connection.send(msg)

        log.debug('Sending: dpid={}, {}.{} -> {}.{}'.format(dpid, packet.src, packet_in.in_port, packet.dst, dst_port))

    def _uninstall_flow(self, dpid, packet, old_port):
        """ Un-installing previous rule. """

        log.debug('Un-installing flow: dpid={}, {} -> {} output via port {}'
                  .format(dpid, "ff:ff:ff:ff:ff:ff", packet.src, old_port))

        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        msg.match.dl_dst = packet.src

        self.connection.send(msg)


from collections import namedtuple
from random import shuffle
from utils import Timer


class LLDPSender(object):
    """ Sends out discovery packets """

    SendItem = namedtuple("LLDPSenderItem", ('dpid', 'port_num', 'packet'))

    def __init__(self, send_cycle_time=1):
        """
        Initialize an LLDP packet sender

        send_cycle_time is the time (in seconds) that this sender will take to
          send all discovery packets.  Thus, it should be the link timeout
          interval at most.

        ttl is the time (in seconds) for which a receiving LLDP agent should
          consider the rest of the data to be valid.  We don't use this, but
          other LLDP agents might.  Can't be 0 (this means revoke).
        """
        # Packets remaining to be sent in this cycle
        self._this_cycle = []

        # Packets we've already sent in this cycle
        self._next_cycle = []

        self._timer = None
        self._send_cycle_time = send_cycle_time

        core.listen_to_dependencies(self)

    def _handle_openflow_PortStatus(self, event):
        """ Track changes to switch ports """
        if event.added:
            self.add_port(event.dpid, event.port, event.ofp.desc.hw_addr)
        elif event.deleted:
            self.del_port(event.dpid, event.port)

    def _handle_openflow_ConnectionUp(self, event):
        self.del_switch(event.dpid, set_timer=False)

        ports = [(p.port_no, p.hw_addr) for p in event.ofp.ports]

        for port_num, port_addr in ports:
            self.add_port(event.dpid, port_num, port_addr, set_timer=False)

        self._set_timer()

    def _handle_openflow_ConnectionDown(self, event):
        self.del_switch(event.dpid)

    def del_switch(self, dpid, set_timer=True):
        self._this_cycle = [p for p in self._this_cycle if p.dpid != dpid]
        self._next_cycle = [p for p in self._next_cycle if p.dpid != dpid]

        if set_timer:
            self._set_timer()

    def del_port(self, dpid, port_num, set_timer=True):
        if port_num > of.OFPP_MAX:
            return

        self._this_cycle = [p for p in self._this_cycle
                            if p.dpid != dpid or p.port_num != port_num]
        self._next_cycle = [p for p in self._next_cycle
                            if p.dpid != dpid or p.port_num != port_num]

        if set_timer:
            self._set_timer()

    def add_port(self, dpid, port_num, port_addr, set_timer=True):
        if port_num > of.OFPP_MAX:
            return

        self.del_port(dpid, port_num, set_timer=False)

        lldpPacket = self.create_discovery_packet(dpid, port_num, port_addr)
        self._next_cycle.append(LLDPSender.SendItem(dpid, port_num, lldpPacket))

        if set_timer:
            self._set_timer()

    def _set_timer(self):
        if self._timer:
            self._timer.cancel()

        self._timer = None
        num_packets = len(self._this_cycle) + len(self._next_cycle)

        if num_packets != 0:
            self._timer = Timer(self._send_cycle_time / float(num_packets),
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

        item = self._this_cycle.pop(0)
        self._next_cycle.append(item)
        core.openflow.sendToDPID(item.dpid, item.packet)

    def create_discovery_packet(self, dpid, port_num, port_addr):
        """ Build discovery packet """

        # chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_LOCAL)
        # chassis_id.id = bytes('dpid:' + hex(long(dpid))[2:-1])
        chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.LLDP_MULTICAST, id=str(dpid))

        port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(port_num))

        ttl = pkt.ttl(ttl=1)

        # sysdesc = pkt.system_description()
        # sysdesc.payload = bytes('dpid:' + hex(long(dpid))[2:-1])

        discovery_packet = pkt.lldp()
        discovery_packet.tlvs.append(chassis_id)
        discovery_packet.tlvs.append(port_id)
        discovery_packet.tlvs.append(ttl)
        # discovery_packet.tlvs.append(sysdesc)
        discovery_packet.tlvs.append(pkt.end_tlv())

        eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
        eth.src = port_addr
        eth.dst = pkt.ETHERNET.LLDP_MULTICAST
        eth.payload = discovery_packet

        po = of.ofp_packet_out(action=of.ofp_action_output(port=port_num))
        po.data = eth.pack()
        return po.pack()


class Discovery(object):
    __metaclass__ = utils.SingletonType

    def __init__(self):
        self.nodes = dict()

        # Listen with a high priority so we get PacketIns as soon as possible
        core.listen_to_dependencies(self, listen_args={'openflow': {'priority': 0xffffffff}})

    def _handle_ConnectionUp(self, event):
        """ Will be called when a switch is added. """
        self.nodes[event.dpid] = event

    def _handle_openflow_ConnectionUp(self, event):
        log.debug('_handle_openflow_ConnectionUp: dpid={}, {}'.format(event.dpid, str(event)))
        pass

    def handle_ConnectionDown(self, event):
        """ Will be called when a switch goes down. """
        del self.nodes[event.dpid]

    def _handle_PortStatus(self, event):
        """ Will be called when a link changes. """
        if event.ofp.desc.config == 1:  # means that link is down
            # event.dpid - switch id
            # event.port - port number
            pass
        pass

    def _handle_PacketIn(self, event):
        """ Will be called when a packet is sent to the controller. """
        if event.parsed.type == pkt.ethernet.LLDP_TYPE:
            lldp_pkt = event.parsed
            lldp_p = lldp_pkt.payload
            ch_id = lldp_p.tlvs[0]
            po_id = lldp_p.tlvs[1]
            r_dpid = int(ch_id.id)
            r_port = int(po_id.id)

        pass


def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)

    core.register('discovery', Discovery())
    core.openflow.addListenerByName("ConnectionUp", start_switch)


# log.info('sending to: {0}'.format(str(dstHostInfo)))
# self.send_packet(packet_in.buffer_id, packet_in.data, dstHostInfo.in_port, packet_in.in_port)