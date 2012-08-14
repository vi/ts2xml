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
packetized_elementary_stream_pids = set()

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

        packetized_elementary_stream_pids.add(elementary_pid)
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


def output_packetized_elementary_stream(f, o, length, payload_start):
    if payload_start:
        o.write("    <elementary_stream_packet>\n")
        byte0 = ord(f.read(1))
        byte1 = ord(f.read(1))
        byte2 = ord(f.read(1))
        byte3 = ord(f.read(1))
        byte4 = ord(f.read(1))
        byte5 = ord(f.read(1))
        if byte0 != 0 or byte1 != 0 or byte2 != 1:
            o.write("        <!-- Start code is "+hex(byte0)+" "+hex(byte1)+" " +hex(byte2)+" instead of 000001 -->\n")
        stream_id = byte3
        stream_type = None
        stream_type_comment = None
        extension_present = False
        if stream_id == 0xBD:
            stream_type = "private_stream_1"
            stream_type_comment = "non-MPEG audio, subpictures"
            extension_present = True
        elif stream_id == 0xBE:
            stream_type = "padding_stream"
            extension_present = False
        elif stream_id == 0xBF:
            stream_type = "private_stream_2"
            stream_type_comment = "Navigation data"
            extension_present = False
        elif stream_id >= 0xC0 and stream_id <= 0xDF:
            stream_type = "mpeg_audio_"+str(stream_id-0xC0)
            extension_present = True
        elif stream_id >= 0xE0 and stream_id <= 0xEF:
            stream_type = "mpeg_video_"+str(stream_id-0xE0)
            extension_present = True
        else:
            stream_type = "unknown_"+hex(stream_id)

        packet_length = (byte4 << 8) | byte5

        o.write("        <stream_type>"+stream_type+"</stream_type>\n")
        o.write("        <packet_length>"+str(packet_length)+"</packet_length>\n")
        
        if extension_present:
            byte6 = ord(f.read(1))
            byte7 = ord(f.read(1))
            byte8 = ord(f.read(1))
                
            if byte6 & 0xC0 != 0x80:
                o.write("        <!-- extensions's reserved is not 10 -->\n")
            pes_scrambling = (byte6 & 0x30 >> 4)
            pes_priority = bool(byte6 & 0x08)
            data_alignment_indicator = bool(byte6 & 0x04)
            copyright = bool(byte6 & 0x02)
            original = bool(byte6 & 0x01)
            pts_present = bool(byte7 & 0x80)
            dts_present = bool(byte7 & 0x40)
            escr_present = bool(byte7 & 0x20)
            es_rate_present = bool(byte7 & 0x10)
            dsm_trick_mode_flag = bool(byte7 & 0x08)
            additional_copy_info_present = bool(byte7 & 0x04)
            PES_crc_present = bool(byte7 & 0x02)
            PES_extension_flag = bool(byte7 & 0x01)
            pes_header_data_length = byte8
            length -= (9 + pes_header_data_length)


            if pes_scrambling:
                o.write("        <PES_scrambling>"+str(pes_scrambling)+"</PES_scrambling>\n")
            if pes_priority:
                o.write("        <PES_priority/>\n")
            if data_alignment_indicator:
                o.write("        <data_alignment_indicator/>\n")
            if copyright:
                o.write("        <copyright/>\n")
            if original:
                o.write("        <original/>\n")
            if es_rate_present:
                o.write("        <es_rate_present/>\n")
            if dsm_trick_mode_flag:
                o.write("        <dsm_trick_mode_flag/>\n")
            if additional_copy_info_present:
                o.write("        <additional_copy_info_present/>\n")
            if PES_crc_present:
                o.write("        <PES_crc_present/>\n")
            if PES_extension_flag:
                o.write("        <PES_extension_flag/>\n")
            
            def read_ts():
                byte1 = ord(f.read(1))
                byte2 = ord(f.read(1))
                byte3 = ord(f.read(1))
                byte4 = ord(f.read(1))
                byte5 = ord(f.read(1))
                if byte1 & 0xC0 != 0x00:
                    o.write("        <!-- first two bits in [PD]TS are not 00 -->\n")
                if byte5 & 0x01 != 0x01 or byte3 & 0x01 != 0x01 or byte1 & 0x01 != 0x01:
                    o.write("        <!-- sync bits are not OK in [PD]TS -->\n")
                ts = ((byte5 & 0xFE) >> 1) | \
                     ((byte4 & 0xFF) << 7) | \
                     ((byte3 & 0xFE) << 14) | \
                     ((byte2 & 0xFF) << 22) | \
                     ((byte1 & 0x0E) << 29)
                ts = ts / 90000.0
                return ts
                

            if pts_present:
                pes_header_data_length -= 5
                pts = read_ts()
                o.write("        <presentation_timestamp>"+str(pts)+"</presentation_timestamp>\n")
            if dts_present:
                pes_header_data_length -= 5
                dts = read_ts()
                o.write("        <decode_timestamp>"+str(dts)+"</decode_timestamp>\n")
            if escr_present:
                pes_header_data_length -= 6
                byte1 = ord(f.read(1))
                byte2 = ord(f.read(1))
                byte3 = ord(f.read(1))
                byte4 = ord(f.read(1))
                byte5 = ord(f.read(1))
                byte6 = ord(f.read(1))
                if byte1 & 0xC0 != 0x00:
                    o.write("        <!-- first two bits of ESCR are not 00 -->\n")
                if byte1 & 0x04 != 0x04 or byte3 & 0x04 != 0x04 or byte5 & 0x04 != 0x04 or byte6 & 0x01 != 0x01:
                    o.write("        <!-- sync bits are not OK in ESCR -->\n")
                escr_base = ((byte5 & 0xF8) >> 3) | \
                            ((byte4 & 0xFF) << 5) | \
                            ((byte3 & 0x03) << 13) | \
                            ((byte3 & 0xF8) << 12) | \
                            ((byte2 & 0xFF) << 18) | \
                            ((byte1 & 0x03) << 26) | \
                            ((byte1 & 0xF8) << 25)
                escr_ext =  ((byte6 & 0xFE) >> 1) | \
                            ((byte5 & 0x03) << 7)
                escr = escr_base / 90000.0 + escr_ext / 27000000.0
                o.write("        <elementary_stream_clock_reference>"+str(escr)+
                        "</elementary_stream_clock_reference>\n"+
                        "        <!-- note that I'm not sure very sure about the ESCR value -->\n")
            if pes_header_data_length<0:
                o.write("        <!-- something wront: remaining PES extended header is " + 
                        str(pes_header_data_length) + " bytes -->\n")
            elif pes_header_data_length:
                resth = f.read(pes_header_data_length)
                o.write("        <decoding_this_not_implemented>" + \
                        binascii.hexlify(resth)+"</decoding_this_not_implemented>\n")

        else:
            length -= 6
        
        rest = f.read(length)
        o.write("        <data>"+binascii.hexlify(rest)+"</data>\n")
        o.write("    </elementary_stream_packet>\n")
    else:
        o.write("    <elementary_stream_packet_continue>\n")
        rest = f.read(length)
        o.write("        <data>"+binascii.hexlify(rest)+"</data>\n")
        o.write("    </elementary_stream_packet_continue>\n")
        
        


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
            elif pid in packetized_elementary_stream_pids:
                output_packetized_elementary_stream(f, o, payload_size, payload_unit_start)
            else:
                if payload_size >= 10000 or payload_size < 0:
                    o.write("    <!-- Malformed packet, resyncing -->\n")
                else:
                    payload = f.read(payload_size)
                    o.write("    <payload>"+binascii.hexlify(payload)+"</payload>\n")
            o.write("</packet>\n")


            
    except StopIteration: pass
    except IOError: pass
    o.write("</ts2xml>\n")


if __name__ == "__main__":
    main()
