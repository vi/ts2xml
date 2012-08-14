#!/usr/bin/env python

import sys
from xml.sax import saxutils
import binascii

def wait_for_sync_byte(f, o):
    signaled = False
    while True:
        b = f.read(1)
        if not b:
            raise StopIteration
        if ord(b) == 0x47:
            return
        if not signaled:
            o.write("<!-- resyncing -->\n")
            signaled=True


program_map_pids = set()

def output_program_association_table(f, o, length, payload_start):
    o.write("    <program_association_table>\n")
    pointer_field = None
    cursor = 0
    if payload_start:
        pointer_field = ord(f.read(1))
        if pointer_field:
            o.write("        <pointer_field>"+str(pointer_field)+"</pointer_field>\n")
        cursor+=1
    table_id = ord(f.read(1));  cursor+=1
    if table_id:
        o.write("        <table_id>"+str(pointer_field)+"</table_id>\n")
    byte3 = ord(f.read(1))   ;  cursor+=1 
    if byte3 & 0x80 != 0x80:
        o.write("        <!-- selection_syntax_indicator is not 1 -->\n")
    if byte3 & 0x40 != 0x00:
        o.write("        <!-- reserved1 is not 0 -->\n")
    if byte3 & 0x30 != 0x30:
        o.write("        <!-- reserved2 is not 11 -->\n")
    if byte3 & 0x0C != 0x00:
        o.write("        <!-- two higher bits of secrion_length is are not 00 -->\n")
    byte4 = ord(f.read(1))  ; cursor+=1
    section_length = byte4 | ((byte3 & 0x07) << 8)
    if section_length:
        o.write("        <section_length>"+str(section_length)+"</section_length>\n")
    byte5 = ord(f.read(1)) ; cursor += 1
    byte6 = ord(f.read(1)) ; cursor += 1
    transport_stream_ID = byte5 << 8 | byte6
    if transport_stream_ID:
        o.write("        <transport_stream_ID>"+str(transport_stream_ID)+"</transport_stream_ID>\n")
    byte7 = ord(f.read(1)) ; cursor += 1
    if byte7 & 0xC0 != 0xC0:
        o.write("        <!-- reserved3 is not 11 -->\n")
    version_number = (byte7 & 0x3E) >> 1
    o.write("        <version_number>"+str(version_number)+"</version_number>\n")
    current_indicator = bool(byte7 & 0x01)
    if not current_indicator:
        o.write("        <not_appliable_yet/>\n")
    section_number = ord(f.read(1)) ; cursor += 1
    last_section_number = ord(f.read(1)) ; cursor += 1

    if last_section_number:
        o.write("        <section_number>"+str(section_number)+"</section_number>\n")
        o.write("        <last_section_number>"+str(last_section_number)+"</last_section_number>\n")
    
    for i in range(0,(section_length-5-4)/4):
        o.write("        <program>\n")
        cursor+=4
        program_num  = (ord(f.read(1)) << 8) | ord(f.read(1))
        b1 = ord(f.read(1))
        b2 = ord(f.read(1))
        if b1 & 0xE0 != 0xE0:
            o.write("            <!-- reserved is not 111 -->\n")
        program_pid = b2 | ((b1 & 0x1F) << 8)
        o.write("            <program_num>"+str(program_num)+"</program_num>\n")
        o.write("            <program_pid>"+hex(program_pid)+"</program_pid>\n")
        o.write("        </program>\n")

        program_map_pids.add(program_pid)
    
    crc32 = f.read(4); cursor+=4

    length -= cursor

    if length>0:
        rest = f.read(length)
        if (rest != '\xff' * length) and (rest != '\x00' * length):
            o.write("        <rest>"+binascii.hexlify(rest)+"</rest>\n")

    o.write("    </program_association_table>\n")


def output_program_map_table(f, o, length, payload_start):
    o.write("    <program_map_table>\n")
    pointer_field = None
    cursor = 0
    if payload_start:
        pointer_field = ord(f.read(1))
        if pointer_field:
            o.write("        <pointer_field>"+str(pointer_field)+"</pointer_field>\n")
        cursor+=1
    table_id = ord(f.read(1));  cursor+=1
    if table_id != 0x02:
        o.write("        <table_id>"+str(pointer_field)+"</table_id>\n")
    byte3 = ord(f.read(1))   ;  cursor+=1 
    if byte3 & 0x80 != 0x80:
        o.write("        <!-- selection_syntax_indicator is not 1 -->\n")
    if byte3 & 0x40 != 0x00:
        o.write("        <!-- reserved1 is not 0 -->\n")
    if byte3 & 0x30 != 0x30:
        o.write("        <!-- reserved2 is not 11 -->\n")
    if byte3 & 0x0C != 0x00:
        o.write("        <!-- two higher bits of secrion_length is are not 00 -->\n")
    byte4 = ord(f.read(1))  ; cursor+=1
    section_length = byte4 | ((byte3 & 0x07) << 8)
    if section_length:
        o.write("        <section_length>"+str(section_length)+"</section_length>\n")
    byte5 = ord(f.read(1)) ; cursor += 1
    byte6 = ord(f.read(1)) ; cursor += 1
    program_num = byte5 << 8 | byte6
    if program_num:
        o.write("        <program_num>"+str(program_num)+"</program_num>\n")
    byte7 = ord(f.read(1)) ; cursor += 1
    if byte7 & 0xC0 != 0xC0:
        o.write("        <!-- reserved3 is not 11 -->\n")
    version_number = (byte7 & 0x3E) >> 1
    o.write("        <version_number>"+str(version_number)+"</version_number>\n")
    current_indicator = bool(byte7 & 0x01)
    if not current_indicator:
        o.write("        <not_appliable_yet/>\n")
    section_number = ord(f.read(1)) ; cursor += 1
    last_section_number = ord(f.read(1)) ; cursor += 1

    byte8 = ord(f.read(1)) ; cursor += 1
    byte9 = ord(f.read(1)) ; cursor += 1
    pcr_pid = byte9 | ((byte8 & 0x1f) << 8)
    o.write("        <general_timecode_stream_PID>"+hex(pcr_pid)+"</general_timecode_stream_PID>\n")
    byte10 = ord(f.read(1)) ; cursor += 1
    byte11 = ord(f.read(1)) ; cursor += 1
    no_program_info_length = False
    program_info_length = byte11 | ((byte10 & 0x0f) << 8) 
    if not program_info_length:
        no_program_info_length = True

    if last_section_number:
        o.write("        <section_number>"+str(section_number)+"</section_number>\n")
        o.write("        <last_section_number>"+str(last_section_number)+"</last_section_number>\n")
    
    section_length -= (9+4)
    while section_length>0:
        o.write("        <stream>\n")

        stream_type = ord(f.read(1))
        o.write("            <stream_type>"+hex(stream_type)+"</stream_type>\n")

        b1 = ord(f.read(1))
        b2 = ord(f.read(1))
        if b1 & 0xE0 != 0xE0:
            o.write("            <!-- reserved is not 111 -->\n")
        elementary_pid = b2 | ((b1 & 0x1F) << 8)
        o.write("            <elementary_pid>"+hex(elementary_pid)+"</elementary_pid>\n")
        b3 = ord(f.read(1))
        b4 = ord(f.read(1))
        if b3 & 0xF0 != 0xF0:
            o.write("            <!-- reserved2 is not 1111 -->\n")
        es_info_length = b4 | ((b3 & 0x0F) << 8)
        
        cursor         += 5+es_info_length
        section_length -= 5+es_info_length
        program_info_length -= 5+es_info_length

        es_info = f.read(es_info_length)

        if es_info_length:
            o.write("            <ES_info>"+binascii.hexlify(es_info)+"</ES_info>\n")
        o.write("        </stream>\n")

        #program_map_pids.add(program_pid)
    if(section_length!=0):
        o.write("        <!-- section_length discrepancy -->\n")
    if not no_program_info_length:
        if(program_info_length!=0):
            o.write("        <!-- program_info_length discrepancy -->\n")
    
    crc32 = f.read(4); cursor+=4

    length -= cursor

    if length>0:
        rest = f.read(length)
        if (rest != '\xff' * length) and (rest != '\x00' * length):
            o.write("        <rest>"+binascii.hexlify(rest)+"</rest>\n")

    o.write("    </program_map_table>\n")


def output_adaptation_field(f, o):
    o.write("    <adaptation_field>\n")
    additional_length = ord(f.read(1))
    if additional_length == 0:
        o.write("    </adaptation_field>\n")
        return 1

    flags = ord(f.read(1))
    discontinuity = bool(flags & 0x80)
    random_access = bool(flags & 0x40)
    elementary_stream_priority = bool(flags & 0x20)
    pcr = bool(flags & 0x10)
    opcr = bool(flags & 0x08)
    splicing_point = bool(flags & 0x04)
    transport_private = bool(flags & 0x02)
    adaptation_field_extension = bool(flags & 0x01)
        
    if discontinuity:    o.write("        <discontinuity/>\n")
    if random_access:    o.write("        <random_access/>\n")
    if elementary_stream_priority:    o.write("        <elementary_stream_priority/>\n")

    length = additional_length+1 # size byte
    additional_length-=1 # flags

    def read_pcr():
        pcr_byte_1 = ord(f.read(1)) # base
        pcr_byte_2 = ord(f.read(1)) # base
        pcr_byte_3 = ord(f.read(1)) # base
        pcr_byte_4 = ord(f.read(1)) # base
        pcr_byte_5 = ord(f.read(1)) # 1 bit base, 6 bits paddding, 1 bit ext
        pcr_byte_6 = ord(f.read(1)) # 8 bits ext

        base = (pcr_byte_1 << (1+8*3)) +  \
               (pcr_byte_2 << (1+8*2)) +  \
               (pcr_byte_3 << (1+8*1)) +  \
               (pcr_byte_4 << (1+8*0)) +  \
               (pcr_byte_5 >> 7)

        ext = ((pcr_byte_5 & 0x01) << 8) + pcr_byte_6

        time = base / 90000.0 + ext / 27000000.0

        return time


    if pcr:
        if additional_length>=6:
            additional_length-=6
            val = read_pcr()
            
            o.write("        <program_clock_reference>"+str(val)+"</program_clock_reference>\n")
    if opcr:
        if additional_length>=6:
            additional_length-=6
            val = read_pcr()
            o.write("        <original_program_clock_reference>"+str(val)+"</original_program_clock_reference>\n")
    if splicing_point:
        if additional_length>=1:
            additional_length-=1
            splice_count = ord(f.read(1))
            o.write("        <splice_countdown>"+str(splice_count)+"</splice_countdown>\n")

    if additional_length:
        o.write("       <!-- ignoring " + str(additional_length) + " bytes -->\n")

    f.read(additional_length)

    o.write("    </adaptation_field>\n")
    return length


def main():
    o = sys.stdout
    o.write("<ts2xml>\n")
    try:
        f = sys.stdin
        while True:
            wait_for_sync_byte(f, o)
            header1 =  ord(f.read(1))
            header2 =  ord(f.read(1))
            header3 =  ord(f.read(1))
            transport_error = bool(header1 & 0x80)
            payload_unit_start = bool(header1 & 0x40)
            transport_priority = bool(header1 & 0x20)
            pid = header2 | ((header1 & 0x1F) << 8)
            scrambling = ((header3 & 0xC0) >> 6)
            have_adaptation_field = bool(header3 & 0x20)
            have_payload = bool(header3 & 0x10)
            continuity_couter = header3 & 0x0F
            
            #print((transport_error, payload_unit_start, transport_priority, pid, scrambling, have_adaptation_field, have_payload, continuity_couter))

            o.write("<packet>\n")
            if transport_error:    o.write("    <transport_error/>\n")
            if payload_unit_start: o.write("    <payload_unit_start/>\n")
            if transport_priority: o.write("    <transport_priority/>\n")
            o.write("    <pid>"+hex(pid)+"</pid>\n")
            if scrambling: o.write("    <scrambling>"+hex(scrambling)+"</scrambling>\n")

            adaptation_field_size = 0
            if have_adaptation_field:
                adaptation_field_size = output_adaptation_field(f, o)

            payload_size = 188 - 4 - adaptation_field_size

            if pid == 0x00:
                output_program_association_table(f, o, payload_size, payload_unit_start) 
            elif pid in program_map_pids:
                output_program_map_table(f, o, payload_size, payload_unit_start)
            else:
                payload = f.read(payload_size)
                o.write("    <payload>"+binascii.hexlify(payload)+"</payload>\n")
            o.write("</packet>\n")
            
    except StopIteration: pass
    except IOError: pass
    o.write("</ts2xml>\n")


if __name__ == "__main__":
    main()
