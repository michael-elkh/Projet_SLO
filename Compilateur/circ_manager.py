#!/usr/bin/env python2
# encoding: utf-8

# Author: adrien.lescourt@hesge.ch
# 04.2014, hepia

from xml.dom import minidom
import sys
import os


def resource_path(relative):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative)
    return os.path.join(relative)


class CircManager():

    """
        This class is used to append multiple 'constant' composant into a base .circ class
        Used to add instructions into a simple instruction ROM designed by LSN student. The ROM is a
        list of constant with a multiplexer
    """
    def __init__(self):
        self.xmldoc = minidom.parse(resource_path('rom_base.circ'))
        self.circuit = self.xmldoc.getElementsByTagName('circuit')[0]

    def append_constant_from_binary_list(self, binary_list):
        pos_X_left = 260
        pos_X_right = 300
        pos_Y = 140
        step_Y = 10
        count = 0
        for elem in binary_list:
            if count % 2 == 0:
                self.__add_component(str((pos_X_left, pos_Y)), '0b' + elem)
            else:
                self.__add_component(str((pos_X_right, pos_Y)), '0b' + elem)
            count += 1
            pos_Y += step_Y
            if count == 32:
                pos_Y = 520
            if count == 64:
                pos_Y = 140
                pos_X_left = 550
                pos_X_right = 590
            if count == 96:
                pos_Y = 520

    def get_XML(self):
        return self.xmldoc.toprettyxml()

    def __add_component(self, loc, val):
        comp = self.xmldoc.createElement('comp')
        comp.setAttribute("lib", '0')
        comp.setAttribute("loc", loc)
        comp.setAttribute("name", 'Constant')
        sub_comp = self.xmldoc.createElement('a')
        sub_comp.setAttribute('name', 'width')
        sub_comp.setAttribute('val', '16')
        comp.appendChild(sub_comp)
        sub_comp = self.xmldoc.createElement('a')
        sub_comp.setAttribute('name', 'value')
        sub_comp.setAttribute('val', val)
        comp.appendChild(sub_comp)
        self.circuit.appendChild(comp)
