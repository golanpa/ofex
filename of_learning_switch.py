""" OpenFlow Exercise - Sample File
This file was created as part of the course Advanced Workshop in IP Networks
in IDC Herzliya.

This code is based on the official OpenFlow tutorial code.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

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

                self._uninstall_flows(dpid, packet)

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
            log.debug('Flooding packet: dpid={}, type={}, src={} port={} -> dst={} port={}'
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

    def _uninstall_flows(self, dpid, packet):
        """ Un-installing all rules to specific destination. """

        log.debug('Un-installing flow: dpid={}, match={{ dst:{} }} delete'
                  .format(dpid, packet.src))

        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        msg.match.dl_dst = packet.src

        self.connection.send(msg)


def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)


# log.info('sending to: {0}'.format(str(dstHostInfo)))
# self.send_packet(packet_in.buffer_id, packet_in.data, dstHostInfo.in_port, packet_in.in_port)

# log.info('Sending: dpid={}, type={}, {}.{} -> {}.{}'
#          .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst, dst_host_info.in_port))
# self.send_packet(packet_in.buffer_id, packet_in.data, dst_host_info.in_port, packet_in.in_port)