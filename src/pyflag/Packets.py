""" File to define a base class for packet handlers.

Packet handlers are similar to scanners but are invoked for each
miscelaneous packet.
"""

class PacketHandler:
    """ Base class for handling individual packets """
    order = 10
    def __init__(self, case):
        self.case = case

    def handle(self, packet):
        """ Abstract method for implementation """

