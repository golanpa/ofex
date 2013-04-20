""" OpenFlow Exercise - Topologies File
This file was created as part of the course Advanced Workshop in IP Networks
in IDC Herzliya.
"""

from mininet.topo import Topo

class Edge:
    """Represents an edge between two entities"""
    
    def __init__(self, left, right):
        self.left = left
        self.right = right

class LoopTopology( Topo ):
    """ This topology class emulates a network with a cycle that should
    be resolved using the Spanning Tree algorithm.

    The topology is illustrated below:

                      +---------+
                      | Host H5 |
                      +----+----+
                           |
                     +-----+-----+
                     | Switch S1 |
                     +-----+-----+
                           |
           +---------------+---------------+
           |                               |
     +-----+-----+                   +-----+-----+
     | Switch S2 |                   | Switch S3 |
     +-----+-----+                   +-----+-----+
           |                               |
           +---------------+---------------+
                           |
                     +-----+-----+
                     | Switch S4 |
                     +-----+-----+
                           |
                      +----+----+
                      | Host H6 |
                      +---------+
    """

    def __init__( self ):
        """Create custom topo."""

        Topo.__init__( self )

        # Set Node IDs for hosts and switches

        # Add Nodes
        switches = [
                self.addSwitch('s1'),
                self.addSwitch('s2'),
                self.addSwitch('s3'),
                self.addSwitch('s4')
            ]
        hosts = [
                self.addHost('h5'),
                self.addHost('h6')
            ]

        # Add Edges
        edges = [   Edge(hosts[0],      switches[0]), 
                    Edge(switches[0],   switches[1]), 
                    Edge(switches[0],   switches[2]), 
                    Edge(switches[1],   switches[3]), 
                    Edge(switches[2],   switches[3]), 
                    Edge(switches[3],   hosts[1])
            ]

        for edge in edges:
            self.addLink( edge.left, edge.right )
            
class SimpleTreeTopology( Topo ):
    """ This topology class emulates a network without a cycle that should
    be work with a simple learning switch.

    The topology is illustrated below:

     +---------+                                        +---------+
     | Host H3 |                                        | Host H5 |
     +----+----+  +------------+       +-------------+  +----+----+
          +-------+1           |       |           2 +-------+
                  | Switch S1 3+-------+1  Switch S2 |
          +-------+2           |       |           3 +-------+
     +----+----+  +------------+       +-------------+  +----+----+
     | Host H4 |                                        | Host H6 |
     +---------+                                        +---------+
    """
    
    def __init__( self ):
        """Create custom topo."""

        Topo.__init__( self )

        # Set Node IDs for hosts and switches

        # Add Nodes
        switches = [
                self.addSwitch('s1'),
                self.addSwitch('s2')
            ]
        hosts = [
                self.addHost('h3'),
                self.addHost('h4'),
                self.addHost('h5'),
                self.addHost('h6')
            ]

        # Add Edges
        edges = [   Edge(hosts[0],      switches[0]), 
                    Edge(hosts[1],      switches[0]), 
                    Edge(switches[0],   switches[1]), 
                    Edge(hosts[2],      switches[1]), 
                    Edge(hosts[3],      switches[1]) 
            ]

        for edge in edges:
            self.addLink( edge.left, edge.right )


class SimpleLoopTopology( Topo ):
    """ This topology class emulates a network with a cycle, in which one switch-switch link
    should start down, then during operation another switch-switch should be taken down and
    the originally down link should be taken up.

    The topology is illustrated below:

     +---------+                                     +---------+
     | Host H4 |                                     | Host H5 |
     +----+----+  +-----------+       +-----------+  +----+----+
          +-------+           |       |           +-------+
                  | Switch S1 +-------+ Switch S2 |
                  +           |       |           +
                  +-----+-----+       +-----+-----+
                        |                   |
                        |   +-----------+   |
                        |   |           |   |
                        +---+ Switch S3 +---+
                            |           |
                            +-----+-----+
                                  |
                             +----+----+
                             | Host H6 |
                             +---------+
"""
    def __init__( self ):
        """Create custom topo."""

        Topo.__init__( self )

        # Set Node IDs for hosts and switches

        # Add Nodes
        switches = [
                self.addSwitch('s1'),
                self.addSwitch('s2'),
                self.addSwitch('s3')
            ]
        hosts = [
                self.addHost('h4'),
                self.addHost('h5'),
                self.addHost('h6')
            ]

        # Add Edges
        edges = [   Edge(hosts[0],      switches[0]), 
                    Edge(hosts[1],		switches[1]), 
                    Edge(hosts[2],      switches[2]), 
                    Edge(switches[0],  	switches[1]),
                    Edge(switches[1],   switches[2]),
                    Edge(switches[2],  	switches[0]) 
            ]

        for edge in edges:
            self.addLink( edge.left, edge.right )
        

topos = { 'LoopTopology': ( lambda: LoopTopology() ) ,
		  'SimpleTreeTopology': ( lambda: SimpleTreeTopology() ),
          'SimpleLoopTopology': ( lambda: SimpleLoopTopology() ) }
