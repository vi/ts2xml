ts2xml reads mpegts file from stdin and dumps it as special XML file containing packets with their headers.

ts2xml is stateful: it reads PATs and PMTs and remembers how PIDs should be handled.

Example of resulting XML file:

    <ts2xml>
    <packet>
        <payload_unit_start/>
        <pid>0x0</pid>
        <program_association_table>
            <section_length>13</section_length>
            <transport_stream_ID>1</transport_stream_ID>
            <version_number>0</version_number>
            <program>
                <program_num>1</program_num>
                <program_pid>0x1000</program_pid>
            </program>
        </program_association_table>
    </packet>
    <packet>
        <payload_unit_start/>
        <pid>0x1000</pid>
        <program_map_table>
            <section_length>23</section_length>
            <program_num>1</program_num>
            <version_number>0</version_number>
            <general_timecode_stream_PID>0x100</general_timecode_stream_PI
            <stream>
                <stream_type>0x1b</stream_type>
                <elementary_pid>0x100</elementary_pid>
            </stream>
            <stream>
                <stream_type>0xf</stream_type>
                <elementary_pid>0x101</elementary_pid>
            </stream>
        </program_map_table>
    </packet>
    <packet>
        <payload_unit_start/>
        <pid>0x100</pid>
        <adaptation_field>
            <random_access/>
            <program_clock_reference>0.7</program_clock_reference>
        </adaptation_field>
        <elementary_stream_packet>
            <stream_type>mpeg_video_0</stream_type>
            <packet_length>6233</packet_length>
            <presentation_timestamp>1.4</presentation_timestamp>
            <data>0000000109f000000001674d400d92420283f6022000000c800002ed
        </elementary_stream_packet>
    </packet>
    <packet>
        <pid>0x100</pid>
        <elementary_stream_packet_continue>
            <data>63e1537ea562e18bead16ab34ee33af6f2d9ef7a6ef856cd54fb2b8f
        </elementary_stream_packet_continue>
    </packet>


The primary use cases of the tool are:

* Learning about MpegTS and PES formats
* Debugging issues with MpegTS

Example invocation (extract raw stream of pid 0x100 to file):

    ./ts2xml.py < q.ts | xml2 | grep 'packet/pid\|/data=' | grep -A 1 '/pid=0x100' | grep 'data=' | cut -f 2- -d= | tr -d '\n' | xxd -r -p | pv > q.raw


xml2ts should follow someday.


For mkv2xml and xml2mkv see https://github.com/vi/mkvparse
