import argparse
import time
import socket
import struct
import binascii
import pprint
import logging
import threading
from copy import copy
import io
import requests

log_format = "[%(asctime)s] [%(levelname)s] - %(message)s"
logging.basicConfig(level=logging.ERROR, format=log_format, filename="/tmp/p4app_logs/int_collector.log")
logger = logging.getLogger('int_collector')


def parse_params():
    parser = argparse.ArgumentParser(description='InfluxDB INT Collector client.')

    parser.add_argument("-i", "--int_port", default=6000, type=int,
        help="UDP port for INT-MD telemetry reports")

    parser.add_argument("-x", "--xd_port", default=6001, type=int,
        help="UDP port for INT-XD telemetry reports")

    parser.add_argument("-H", "--host", default="localhost",
        help="InfluxDB server address")

    parser.add_argument("-D", "--database", default="int_telemetry_db",
        help="Unused - kept for compatibility")

    parser.add_argument("--token", default="my-super-secret-token",
        help="InfluxDB v2 API token")

    parser.add_argument("--org", default="int-project",
        help="InfluxDB v2 organisation")

    parser.add_argument("--bucket", default="int_telemetry",
        help="InfluxDB v2 bucket")

    parser.add_argument("-p", "--period", default=1, type=int,
        help="Time period to push data in normal condition")

    parser.add_argument("-d", "--debug_mode", default=0, type=int,
        help="Set to 1 to print debug information")

    return parser.parse_args()


class HopMetadata:
    def __init__(self, data, ins_map, int_version=1):
        self.data = data
        self.ins_map = ins_map

        self.__parse_switch_id()
        self.__parse_ports()
        self.__parse_hop_latency()
        self.__parse_queue_occupancy()
        self.__parse_ingress_timestamp()
        self.__parse_egress_timestamp()
        if int_version == 0:
            self.__parse_queue_congestion()
        elif int_version >= 1:
            self.__parse_l2_ports()
        self.__parse_egress_port_tx_util()

    def __parse_switch_id(self):
        if self.ins_map & 0x80:
            self.switch_id = int.from_bytes(self.data.read(4), byteorder='big')
            logger.debug('parse switch id: %d' % self.switch_id)

    def __parse_ports(self):
        if self.ins_map & 0x40:
            self.l1_ingress_port_id = int.from_bytes(self.data.read(2), byteorder='big')
            self.l1_egress_port_id = int.from_bytes(self.data.read(2), byteorder='big')
            logger.debug('parse ingress port: %d, egress_port: %d' % (self.l1_ingress_port_id, self.l1_egress_port_id))

    def __parse_hop_latency(self):
        if self.ins_map & 0x20:
            self.hop_latency = int.from_bytes(self.data.read(4), byteorder='big')
            logger.debug('parse hop latency: %d' % self.hop_latency)

    def __parse_queue_occupancy(self):
        if self.ins_map & 0x10:
            self.queue_occupancy_id = int.from_bytes(self.data.read(1), byteorder='big')
            self.queue_occupancy = int.from_bytes(self.data.read(3), byteorder='big')
            logger.debug('parse queue_occupancy_id: %d, queue_occupancy: %d' % (self.queue_occupancy_id, self.queue_occupancy))

    def __parse_ingress_timestamp(self):
        if self.ins_map & 0x08:
            self.ingress_timestamp = int.from_bytes(self.data.read(8), byteorder='big')
            logger.debug('parse ingress_timestamp: %d' % self.ingress_timestamp)

    def __parse_egress_timestamp(self):
        if self.ins_map & 0x04:
            self.egress_timestamp = int.from_bytes(self.data.read(8), byteorder='big')
            logger.debug('parse egress_timestamp: %d' % self.egress_timestamp)

    def __parse_queue_congestion(self):
        if self.ins_map & 0x02:
            self.queue_congestion_id = int.from_bytes(self.data.read(1), byteorder='big')
            self.queue_congestion = int.from_bytes(self.data.read(3), byteorder='big')

    def __parse_l2_ports(self):
        if self.ins_map & 0x02:
            self.l2_ingress_port_id = int.from_bytes(self.data.read(2), byteorder='big')
            self.l2_egress_port_id = int.from_bytes(self.data.read(2), byteorder='big')

    def __parse_egress_port_tx_util(self):
        if self.ins_map & 0x01:
            self.egress_port_tx_util = int.from_bytes(self.data.read(4), byteorder='big')

    def unread_data(self):
        return self.data

    def __str__(self):
        attrs = vars(self)
        try:
            del attrs['data']
            del attrs['ins_map']
        except Exception as e:
            logger.error(e)
        return pprint.pformat(attrs)


def ip2str(ip):
    return "{}.{}.{}.{}".format(ip[0], ip[1], ip[2], ip[3])


UDP_OFFSET = 14 + 20 + 8
TCP_OFFSET = 14 + 20 + 20


class IntReport():
    def __init__(self, data):
        orig_data = data

        self.int_report_hdr = data[:16]
        self.ver = self.int_report_hdr[0] >> 4

        if self.ver != 1:
            raise Exception("Unsupported INT report version %s" % self.ver)

        self.len = self.int_report_hdr[0] & 0x0f
        self.nprot = self.int_report_hdr[1] >> 5
        self.rep_md_bits = (self.int_report_hdr[1] & 0x1f) + (self.int_report_hdr[2] >> 7)
        self.d = self.int_report_hdr[2] & 0x01
        self.q = self.int_report_hdr[3] >> 7
        self.f = (self.int_report_hdr[3] >> 6) & 0x01
        self.hw_id = self.int_report_hdr[3] & 0x3f
        self.switch_id, self.seq_num, self.ingress_tstamp = struct.unpack('!3I', orig_data[4:16])

        self.ip_hdr = data[30:50]
        self.udp_hdr = data[50:58]
        protocol = self.ip_hdr[9]
        self.flow_id = {
            'srcip': ip2str(self.ip_hdr[12:16]),
            'dstip': ip2str(self.ip_hdr[16:20]),
            'scrp': struct.unpack('!H', self.udp_hdr[:2])[0],
            'dstp': struct.unpack('!H', self.udp_hdr[2:4])[0],
            'protocol': self.ip_hdr[9],
        }

        offset = 16
        if protocol == 17:
            offset = offset + UDP_OFFSET
        if protocol == 6:
            offset = offset + TCP_OFFSET

        self.int_shim = data[offset:offset + 4]
        self.int_type = self.int_shim[0]
        self.int_data_len = int(self.int_shim[2]) - 3

        if self.int_type != 1:
            raise Exception("Unsupported INT type %s" % self.int_type)

        self.int_hdr = data[offset + 4:offset + 12]
        self.int_version = self.int_hdr[0] >> 4
        if self.int_version == 0:
            self.hop_count = self.int_hdr[3]
        elif self.int_version == 1:
            self.hop_metadata_len = int(self.int_hdr[2] & 0x1f)
            self.remaining_hop_cnt = self.int_hdr[3]
            self.hop_count = int(self.int_data_len / self.hop_metadata_len)
            logger.debug("hop_metadata_len: %d, int_data_len: %d, remaining_hop_cnt: %d, hop_count: %d" % (
                self.hop_metadata_len, self.int_data_len, self.remaining_hop_cnt, self.hop_count))
        else:
            raise Exception("Unsupported INT version %s" % self.int_version)

        self.ins_map = int.from_bytes(self.int_hdr[4:6], byteorder='big')
        first_slice = (self.ins_map & 0b0000111100000000) << 4
        second_slice = (self.ins_map & 0b1111000000000000) >> 4
        self.ins_map = (first_slice + second_slice) >> 8

        self.int_meta = data[offset + 12:]
        self.hop_metadata = []
        self.int_meta = io.BytesIO(self.int_meta)
        for i in range(self.hop_count):
            try:
                hop = HopMetadata(self.int_meta, self.ins_map, self.int_version)
                self.int_meta = hop.unread_data()
                self.hop_metadata.append(hop)
            except Exception as e:
                logger.error(e)
                break

    def __str__(self):
        hop_info = ''
        for hop in self.hop_metadata:
            hop_info += str(hop) + '\n'
        flow_tuple = "src_ip: %(srcip)s, dst_ip: %(dstip)s, src_port: %(scrp)s, dst_port: %(dstp)s, protocol: %(protocol)s" % self.flow_id
        additional_info = "sw: %s, seq: %s, int version: %s, ins_map: 0x%x, hops: %d" % (
            self.switch_id, self.seq_num, self.int_version, self.ins_map, self.hop_count)
        return "\n".join([flow_tuple, additional_info, hop_info])


class IntXdReport():
    def __init__(self, data):
        self.ver = data[0] >> 4
        if self.ver != 1:
            raise Exception("Unsupported XD report version %s" % self.ver)

        self.switch_id, self.seq_num, self.ingress_tstamp = struct.unpack('!3I', data[4:16])

        ip_start = 16 + 14
        self.ip_hdr  = data[ip_start:ip_start + 20]
        self.udp_hdr = data[ip_start + 20:ip_start + 28]

        self.flow_id = {
            'srcip':    ip2str(self.ip_hdr[12:16]),
            'dstip':    ip2str(self.ip_hdr[16:20]),
            'scrp':     struct.unpack('!H', self.udp_hdr[:2])[0],
            'dstp':     struct.unpack('!H', self.udp_hdr[2:4])[0],
            'protocol': self.ip_hdr[9],
        }

        o = 16 + 14 + 20 + 8
        self.xd_switch_id      = struct.unpack('!I',  data[o:o+4])[0];  o += 4
        self.ingress_port, self.egress_port = struct.unpack('!HH', data[o:o+4]);  o += 4
        self.hop_latency       = struct.unpack('!I',  data[o:o+4])[0];  o += 4
        self.q_id              = data[o]
        self.q_occupancy       = int.from_bytes(data[o+1:o+4], 'big');  o += 4
        self.ingress_timestamp = struct.unpack('!Q',  data[o:o+8])[0];  o += 8
        self.egress_timestamp  = struct.unpack('!Q',  data[o:o+8])[0]

    def __str__(self):
        return ("XD sw=%d seq=%d %s->%s in_port=%d out_port=%d latency=%d q=%d" % (
            self.xd_switch_id, self.seq_num,
            self.flow_id['srcip'], self.flow_id['dstip'],
            self.ingress_port, self.egress_port,
            self.hop_latency, self.q_occupancy))


class IntCollector():

    def __init__(self, influx, period):
        self.influx = influx
        self.reports = []
        self.last_dstts = {}
        self.last_reordering = {}
        self.last_hop_ingress_timestamp = {}
        self.period = period
        self.last_send = time.time()

    def add_report(self, report):
        self.reports.append(report)
        reports_cnt = len(self.reports)
        if reports_cnt > 100 or time.time() - self.last_send > self.period:
            logger.info("Sending %d reports to influx" % reports_cnt)
            self.__send_reports()
            self.last_send = time.time()

    def add_xd_report(self, report):
        point = {
            "measurement": "int_telemetry",
            "tags": {
                **report.flow_id,
                "int_mode":  "XD",
                "switch_id": str(report.xd_switch_id),
            },
            "time": int(time.time() * 1e9),
            "fields": {
                "seq":            float(report.seq_num),
                "hop_delay":      float(report.hop_latency),
                "q_occupancy":    float(report.q_occupancy),
                "ingress_port":   float(report.ingress_port),
                "egress_port":    float(report.egress_port),
                "ingress_tstamp": float(report.ingress_timestamp),
                "egress_tstamp":  float(report.egress_timestamp),
            }
        }
        try:
            lines = self.__to_line_protocol([point])
            self.__write_to_influx(lines)
            logger.info("XD report written: %s" % str(report))
        except Exception as e:
            logger.exception("Failed to write XD report: %s" % e)

    def __to_line_protocol(self, json_body):
        lines = []
        for point in json_body:
            measurement = point['measurement']
            tags = ','.join('%s=%s' % (k, str(v).replace(' ', '\\ '))
                            for k, v in sorted(point['tags'].items()))
            fields = ','.join('%s=%s' % (k, v)
                              for k, v in point['fields'].items())
            ts = point.get('time', int(time.time() * 1e9))
            lines.append('%s,%s %s %d' % (measurement, tags, fields, ts))
        return '\n'.join(lines)

    def __write_to_influx(self, lines):
        url = '%s/api/v2/write?org=%s&bucket=%s&precision=ns' % (
            self.influx['base_url'], self.influx['org'], self.influx['bucket'])
        resp = self.influx['session'].post(url, data=lines.encode('utf-8'))
        if resp.status_code != 204:
            logger.error("InfluxDB write failed: %s %s" % (resp.status_code, resp.text))
            raise Exception("InfluxDB write failed: %d" % resp.status_code)

    def __prepare_e2e_report(self, report, flow_key):
        try:
            origin_timestamp = report.hop_metadata[-1].ingress_timestamp
            destination_timestamp = report.hop_metadata[0].ingress_timestamp
        except Exception as e:
            origin_timestamp, destination_timestamp = 0, 0
            logger.error("ingress_timestamp in the INT hop is required, %s" % e)

        json_report = {
            "measurement": "int_telemetry",
            "tags": dict(list(report.flow_id.items()) + [("int_mode", "MD")]),
            "time": int(time.time() * 1e9),
            "fields": {
                "origts": 1.0 * origin_timestamp,
                "dstts":  1.0 * destination_timestamp,
                "seq":    1.0 * report.seq_num,
                "delay":  1.0 * (destination_timestamp - origin_timestamp),
            }
        }

        if flow_key in self.last_dstts:
            json_report["fields"]["sink_jitter"] = 1.0 * destination_timestamp - self.last_dstts[flow_key]

        if flow_key in self.last_reordering:
            json_report["fields"]["reordering"] = 1.0 * report.seq_num - self.last_reordering[flow_key] - 1

        self.last_dstts[flow_key] = destination_timestamp
        self.last_reordering[flow_key] = report.seq_num
        return json_report

    def __prepare_hop_report(self, report, index, hop, flow_key):
        tags = copy(report.flow_id)
        tags['hop_index'] = index
        tags['int_mode'] = 'MD'
        json_report = {
            "measurement": "int_telemetry",
            "tags": tags,
            "time": int(time.time() * 1e9),
            "fields": {}
        }

        flow_hop_key = flow_key + str(index)

        if flow_hop_key in self.last_hop_ingress_timestamp:
            if "ingress_timestamp" in vars(hop):
                json_report["fields"]["hop_jitter"] = hop.ingress_timestamp - self.last_hop_ingress_timestamp[flow_hop_key]

        if "hop_latency" in vars(hop):
            json_report["fields"]["hop_delay"] = float(hop.hop_latency)

        if "ingress_timestamp" in vars(hop) and index > 0:
            json_report["fields"]["link_delay"] = float(hop.ingress_timestamp - self.last_hop_delay)
            self.last_hop_delay = hop.ingress_timestamp

        if "ingress_timestamp" in vars(hop):
            self.last_hop_ingress_timestamp[flow_hop_key] = hop.ingress_timestamp

        return json_report

    def __prepare_reports(self, report):
        flow_key = "%(srcip)s,%(dstip)s,%(scrp)s,%(dstp)s,%(protocol)s" % report.flow_id
        reports = []
        reports.append(self.__prepare_e2e_report(report, flow_key))
        self.last_hop_delay = report.hop_metadata[-1].ingress_timestamp
        for index, hop in enumerate(reversed(report.hop_metadata)):
            reports.append(self.__prepare_hop_report(report, index, hop, flow_key))
        return reports

    def __send_reports(self):
        json_body = []
        for report in self.reports:
            if report.hop_metadata:
                json_body.extend(self.__prepare_reports(report))
            else:
                logger.warning("Empty report metadata: %s" % str(report))
        if json_body:
            try:
                lines = self.__to_line_protocol(json_body)
                self.__write_to_influx(lines)
                logger.info("%d MD reports sent to InfluxDB v2" % len(json_body))
            except Exception as e:
                logger.exception(e)
        self.reports = []


def influx_client(args):
    if ':' in args.host:
        host, port = args.host.split(':')
    else:
        host = args.host
        port = 8086

    session = requests.Session()
    session.headers.update({
        'Authorization': 'Token %s' % args.token,
        'Content-Type': 'text/plain; charset=utf-8',
    })

    return {
        'session':  session,
        'base_url': 'http://%s:%s' % (host, port),
        'org':      args.org,
        'bucket':   args.bucket,
    }


def start_md_listener(args, collector):
    bufferSize = 65565
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.int_port))
    logger.info("MD listener on UDP port %d" % args.int_port)
    print("MD listener on UDP port %d" % args.int_port)
    while True:
        message, address = sock.recvfrom(bufferSize)
        logger.info("MD report (%d bytes) from %s" % (len(message), str(address)))
        logger.debug(binascii.hexlify(message))
        try:
            report = IntReport(message)
            if report:
                collector.add_report(report)
        except Exception as e:
            logger.exception("MD parse error")


def start_xd_listener(args, collector):
    bufferSize = 65565
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.xd_port))
    logger.info("XD listener on UDP port %d" % args.xd_port)
    print("XD listener on UDP port %d" % args.xd_port)
    while True:
        message, address = sock.recvfrom(bufferSize)
        logger.info("XD report (%d bytes) from %s" % (len(message), str(address)))
        try:
            report = IntXdReport(message)
            logger.info(str(report))
            collector.add_xd_report(report)
        except Exception as e:
            logger.exception("XD parse error")


def start_udp_server(args):
    influx = influx_client(args)
    collector = IntCollector(influx, args.period)

    t_md = threading.Thread(target=start_md_listener, args=(args, collector))
    t_xd = threading.Thread(target=start_xd_listener, args=(args, collector))
    t_md.daemon = True
    t_xd.daemon = True
    t_md.start()
    t_xd.start()
    print("INT Collector running - MD port %d, XD port %d" % (args.int_port, args.xd_port))
    t_md.join()


if __name__ == "__main__":
    args = parse_params()
    if args.debug_mode > 0:
        logger.setLevel(logging.DEBUG)
    start_udp_server(args)