""" OpenFlow Exercise - Sample File
This file was created as part of the course Advanced Workshop in IP Networks
in IDC Herzliya.

This code is based on the official OpenFlow tutorial code.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


class HostInfo(object):
    def __init__(self, eth_addr, in_port=-1):
        self.eth_addr = eth_addr
        self.in_port = in_port
        self.rule_installed = False

    def __str__(self):
        return 'mac={}, in_port={}, installed={}'.format(self.eth_addr, self.in_port, self.rule_installed)


class LearningSwitch(object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_host = dict()

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
        Implement switch-like behavior -- if destination is know - send only to the learnt port, otherwise, send all
        packets to all ports besides the input port.
        """

        dpid = self.connection.dpid

        # log.debug('act_like_switch: dpid={}, type={}, {}.{} -> {}'
        #           .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst))

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

        # log.debug('act_like_switch: finished: dpid={}'.format(dpid))

    def _install_flow(self, dpid, packet, packet_in, dst_port):
        """
        Installing rule in switch. Rule is from any source to specific destination via dst_port
        """

        log.debug('Installing flow: dpid={}, {} -> {} output via port {}'
                  .format(dpid, "ff:ff:ff:ff:ff:ff", packet.dst, dst_port))

        msg = of.ofp_flow_mod()
        msg.match.dl_dst = packet.dst
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
        """
        Un-installing previous rule.
        """

        log.debug('Un-installing flow: dpid={}, {} -> {} output via port {}'
                  .format(dpid, "ff:ff:ff:ff:ff:ff", packet.src, old_port))

        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        msg.match.dl_dst = packet.src

        self.connection.send(msg)


def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        LearningSwitch(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)


# log.info('sending to: {0}'.format(str(dstHostInfo)))
# self.send_packet(packet_in.buffer_id, packet_in.data, dstHostInfo.in_port, packet_in.in_port)