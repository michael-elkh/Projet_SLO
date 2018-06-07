#!/usr/bin/env python2
# encoding: utf-8

# Author: adrien.lescourt@hesge.ch
# 04.2014, hepia

import sys
import os
from circ_manager import CircManager


def error_message(message, error_level='FATAL ERROR'):
    if error_level is not None:
        print '***', error_level, '***'
    print message
    sys.exit(0)

class LogiCompiler():

    specialchar = ['+', '-', '<<', '>>', '=', '[', ']', '#']

    comment_char = '#'

    opcode = {'+': '0000',
              '-': '0001',
              '<<': '0010',
              '>>': '0011',
              'asr': '0100',
              'and': '0101',
              'or': '0110',
              'not': '0111',
              '=': '1000',
              'par' : '1001',
              'bcz': '1010',
              'bcn': '1010',
              'bcc': '1010',
              'bcv': '1010',
              'b': '1011',
              '[': '1100',
              ']': '1101',
              'gr': '1110',
              'gw': '1111',
              }

    condition = {'bcz': '1000',
                 'bcn': '0100',
                 'bcc': '0010',
                 'bcv': '0001'}

    register = {'r0': '000',
                'r1': '001',
                'r2': '010',
                'r3': '011',
                'r4': '100',
                'r5': '101',
                'r6': '110',
                'r7': '111'}

    def get_binary_list(self, assembly_code):
        """
            Read the assembly_code list and return the corresponding binary_code list
        """
        self.current_line = 0
        binary_list = []
        (all_operands, label_list) = self.__get_operands(assembly_code)

        if self.__has_multiple_label([elem[0][0] for elem in label_list]):
            error_message('A label is present more than once!')

        for operands in all_operands:
            self.current_line += 1
            if operands is None:  # blank line or comment
                continue
            try:
                instruction = self.Instruction(operands, label_list)
            except:
                error_message('On line ' + str(self.current_line))
            if instruction.data is not None:
                if instruction.data is 'label':
                    print operands[0][0]
                else:
                    print 'N°', self.current_line-1, ':', instruction.data, '-', str.format('0x{:04X}', int(hex(int(instruction.data, 2)), 16)), ':', ' '.join(operands[0])
                    binary_list.append(instruction.data)
            else:
                error_message('On line ' + str(self.current_line))
        return binary_list

    def __get_operands(self, assembly_code):
        """
            Return an operands list for every assembly line (operands, instruction_line),
            and an array of label (label, instruction_line)
        """
        current_line = 0
        instruction_line = 1
        all_operands = []
        label_list = []
        for assembly_line in assembly_code:
            current_line += 1
            assembly_line = self.__add_spaces(assembly_line)
            if len(assembly_line) < 1 or self.__is_comment(assembly_line):
                all_operands.append(None)
            else:
                operands = assembly_line.split()
                if self.__is_label(operands):
                    label_list.append((operands, instruction_line))
                else:
                    instruction_line += 1
                all_operands.append((operands, instruction_line - 1))
        return (all_operands, label_list)

    def __add_spaces(self, line):
        if '=' in line or '[' in line:
            for op in LogiCompiler.specialchar:
                line = line.replace(op, ' ' + op + ' ')
            return ' '.join(line.split()).strip()
        return line.strip()

    def __is_comment(self, line):
        return line[0] == LogiCompiler.comment_char

    def __is_label(self, operands):
        return operands[0].find(':') != -1

    def __has_multiple_label(self, label_list):
        return len(label_list) != len(set(label_list))

    class Instruction():
        def __init__(self, operands_with_line, label_with_line):
            self.load_size = 8
            self.jump_cond_size = 8
            self.jump_size = 12
            self.perif_size = 8
            operands = operands_with_line[0]
            line_nbr = operands_with_line[1]
            self.data = None
            operands_size = len(operands)
            if operands_size == 1:
                self.data = self.__get_binary_from_1_operands(operands)
            if operands_size == 2:
                self.data = self.__get_binary_from_2_operands(operands, line_nbr, label_with_line)
            if operands_size == 3:
                self.data = self.__get_binary_from_3_operands(operands)
            elif operands_size == 4:
                self.data = self.__get_binary_from_4_operands(operands)
            elif operands_size == 5:
                self.data = self.__get_binary_from_5_operands(operands)
            elif operands_size == 10:
                self.data = self.__get_binary_from_10_operands(operands)

        def __get_binary_from_1_operands(self, operands):
                if operands[0][-1] != ':' or not operands[0][:-1].isalnum():
                    error_message('Label must be alphanumeric and end with colon', None)
                    return
                return 'label'

        def __get_binary_from_2_operands(self, operands, line_nbr, label_with_line):
                if operands[0] not in LogiCompiler.opcode:
                    print 'Error:', operands[0], 'not reconized'
                    return
                opcode = LogiCompiler.opcode[operands[0]]
                # bcz / bcn / bcc / bcv
                if operands[0] in LogiCompiler.condition:
                    cond = LogiCompiler.condition[operands[0]]
                    jump_offset = self.__get_jump_offset(operands[1], line_nbr, label_with_line)
                    jump = self.__num_to_binary(jump_offset, self.jump_cond_size)
                    return opcode + cond + jump
                # b
                elif operands[0] == 'b':
                    jump_offset = self.__get_jump_offset(operands[1], line_nbr, label_with_line)
                    jump = self.__num_to_binary(jump_offset, self.jump_size)
                    return opcode + jump

        def __get_jump_offset(self, operand, line_nbr, label_with_line):
            if self.__is_integer(operand):
                return operand
            else:
                label_pos = [elem[1] for elem in label_with_line if elem[0][0] == (operand + ':')]
                if not label_pos:
                    error_message('"' + operand + '" label not found')
                else:
                    return str(label_pos[0] - line_nbr)

        def __get_binary_from_3_operands(self, operands):
                if operands[1] not in LogiCompiler.opcode:
                    print 'Error:', operands[1], 'not reconized'
                    return
                # Affectation
                opcode = LogiCompiler.opcode[operands[1]]
                result = LogiCompiler.register[operands[0]]
                reserved = '0'
                load = self.__num_to_binary(operands[2], self.load_size)
                return opcode + result + reserved + load

        def __get_binary_from_4_operands(self, operands):
                if operands[2] not in LogiCompiler.opcode:
                    print 'Error:', operands[2], 'not reconized'
                    return
                # asr / not /parity
                opcode = LogiCompiler.opcode[operands[2]]
                result = LogiCompiler.register[operands[0]]
                source_0 = LogiCompiler.register[operands[3]]
                source_1 = '000'
                reserved = '000'
                return opcode + result + source_0 + source_1 + reserved

        def __get_binary_from_5_operands(self, operands):
                # ldr
                if operands[2] == '[' and operands[4] == ']':
                    opcode = LogiCompiler.opcode[operands[2]]
                    result = LogiCompiler.register[operands[0]]
                    reserved = '0'
                    perif = self.__num_to_binary(operands[3], self.perif_size)
                    return opcode + result + reserved + perif

                # str
                if operands[0] == '[' and operands[2] == ']':
                    opcode = LogiCompiler.opcode[operands[2]]
                    result = LogiCompiler.register[operands[4]]
                    reserved = '0'
                    perif = self.__num_to_binary(operands[1], self.perif_size)
                    return opcode + result + reserved + perif

                # add / sub / shift / or / and
                else:
                    if operands[3] not in LogiCompiler.opcode:
                        print 'Error:', operands[3], 'not reconized'
                        return
                    opcode = LogiCompiler.opcode[operands[3]]
                    result = LogiCompiler.register[operands[0]]
                    source_0 = LogiCompiler.register[operands[2]]
                    source_1 = ''
                    
                    if operands[3] == '<<' or operands[3] == '>>':
                        source_1 = self.__num_to_binary(operands[4], 3)
                    else:
                        source_1 = LogiCompiler.register[operands[4]]
                    reserved = '000'
                    return opcode + result + source_0 + source_1 + reserved

        def __get_binary_from_10_operands(self, operands):
            # GR / GW
            if operands[0] not in LogiCompiler.opcode:
                print 'Error:', operands[0], 'not reconized'
                return
            opcode = LogiCompiler.opcode[operands[0]]
            data = LogiCompiler.register[operands[2]]
            ah = LogiCompiler.register[operands[5]]
            al = LogiCompiler.register[operands[8]]
            reserved = '000'
            return opcode + data + ah + al + reserved

        def __num_to_binary(self, num, bits):
            if len(num) >= 2:
                prefix = num[:2]
                if prefix == '0x' or prefix == '0X':
                    return self.__hex_to_binary(num, bits)
                elif prefix == '0b' or prefix == '0B':
                    return self.__bin_to_binary(num, bits)
            return self.__int_to_binary(num, bits)

        def __int_to_binary(self, num, bits):
            num = int(num)
            binary = ''
            while bits:
                binary = ('1' if num & 1 else '0') + binary
                bits = bits - 1
                num = num >> 1
            return binary

        def __hex_to_binary(self, hexnum, bits):
            return bin(int(hexnum, 16))[2:].zfill(bits)

        def __bin_to_binary(self, binnum, bits):
            if len(binnum) > bits+2:
                print binnum, 'size must not be longer than', bits, 'bits'
                return
            elif len(binnum) <= 2:
                print binnum, 'is too short'
                return
            return binnum[2:].zfill(bits)

        def __is_integer(self, nbr):
            try:
                int(nbr)
                return True
            except ValueError:
                return False

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'usage: ./logi_compiler lsn_assembly_file output_file.circ'
        sys.exit(0)
    in_file = sys.argv[1]
    out_file = sys.argv[2]
    assembly = [line.rstrip().lower() for line in open(in_file, 'r')]
    logicomp = LogiCompiler()
    binary_list = logicomp.get_binary_list(assembly)
    if len(binary_list) > 128:
        print len(binary_list), 'instructions found. Max limit is 128'
        sys.exit(0)
    else:
        while(len(binary_list) < 128):
            binary_list.append('0000000000000000')
    circ_manager = CircManager()
    circ_manager.append_constant_from_binary_list(binary_list)
    if os.path.isfile(out_file):
        os.remove(out_file)
    f = open(out_file, 'w')
    for char in circ_manager.get_XML():
        f.write(char)
    f.close()
    print out_file, 'successfully generated'
