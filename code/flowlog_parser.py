#!/usr/bin/env python3

""" AWS flow logs custom analyzer """

import csv
import socket
import threading

from abc import ABC, abstractmethod
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from itertools import islice

## Constants ##
TAGMAP_PORT_IDX = 0
TAGMAP_PROTO_IDX = 1
TAGMAP_TAG_IDX = 2

IPMF_PORT_IDX = 0
IPMF_PROTO_IDX = 1

CHUNK_SIZE = 1000  # lines

TAG_COUNT_FH = "\nTag Counts:\nTag,Count\n"
COMB_COUNT_FH = "\nPort/Protocol Combination Counts:\nPort,Protocol,Count\n"

V2_FIELDS_COUNT = 14
V2_DST_PORT_IDX = 6
V2_PROTO_NUM_IDX = 7

DEBUG = True


## Exceptions ##
class FlowLogParserException(Exception):
    """ Flow logs exception class """


class TagMappingsException(Exception):
    """ Tag mappings exception class """


class ProtoMappingsException(Exception):
    """ Proto map exception class """


## Helper functions ##
def read_csv_file(fname):
    """ Helper function to read CSV file """
    buff = []
    try:
        with open(fname, mode='r') as file_handle:
            csv_file = csv.reader(file_handle)
            for line in csv_file:
                buff.append(line)
    except IOError:
        pass

    return buff


class TagMappings:
    """ Helper class for tags processing """

    def __init__(self, fname):
        self.fname = fname

    def process(self):
        buff = []
        try:
            for line in read_csv_file(self.fname):
                if line[TAGMAP_PORT_IDX] == "dstport":
                    continue
                buff.append((
                    int(line[TAGMAP_PORT_IDX]),
                    line[TAGMAP_PROTO_IDX],
                    line[TAGMAP_TAG_IDX],
                ))
        except (IndexError, ValueError) as error:
            raise TagMappingsException(
                "Error reading mappings file -{}".format(str(error)))
        return buff


class ProtoMappings:
    """ Helper class for protocol mappings processing """

    def __init__(self, fname):
        self.fname = fname

    def process(self):
        buff = []
        try:
            for line in read_csv_file(self.fname):
                buff.append((
                    int(line[IPMF_PORT_IDX]),
                    line[IPMF_PROTO_IDX].lower(),
                ))
        except ValueError as error:
            pass  # for Unassigned port range
        except IndexError as error:
            raise ProtoMappingsException(
                "Error reading protocol mappings file = {}".format(str(error)))
        return buff


class GenericFlowLogParser(ABC):
    """ Abstract class representing a flow log parser object.

        Requires the child class to provide implementation for the following
        methods for non default version specific handling:
        1. _analyze_flow_logs()

    """

    def __init__(self,
                 version,
                 logs,
                 mappings,
                 output,
                 proto_map_file=None,
                 logger=None):
        # instance variables
        self.version = version
        self.flowlogs = logs
        self.mapfile = mappings
        self.outputfile = output
        self.proto_map_file = proto_map_file
        self.logger = logger

        # data structures to hold processed info
        self.tag_map = {}
        self.table = {}
        self.mappings = []

        # result dicts
        self.tag_count = defaultdict(int)
        self.combinations_count = defaultdict(int)

        # lock for results dicts updates
        self.counts_lock = threading.Lock()

    def log(self, msg):
        # info only for now
        if self.logger:
            self.logger.info(msg)

    def read_mappings_file(self):
        if not self.mapfile:
            return

        self.log("Reading mappings file ..")
        tag_mp = TagMappings(self.mapfile)

        try:
            buff = tag_mp.process()
        except TagMappingsException as error:
            raise FlowLogParserException(str(error))

        self.log("Generating tag maps ..")
        for entry in buff:
            self.tag_map[(entry[0], entry[1])] = entry[2]

    def read_proto_mappings(self):
        self.log("Reading proto mappings file..")
        if self.proto_map_file:
            proto_mappings = ProtoMappings(self.proto_map_file)
            try:
                for entry in proto_mappings.process():
                    self.table[entry[0]] = entry[1]
            except ProtoMappingsException as error:
                raise FlowLogParserException(str(error))
        else:
            prefix = "IPPROTO_"
            self.table = {
                num: name[len(prefix):]
                for name, num in vars(socket).items()
                if name.startswith(prefix)
            }

    @abstractmethod
    def _analyze_flow_logs(self, lines):
        pass

    def analyze_flow_logs(self):
        if not self.flowlogs:
            return

        # Implementation Note:
        # I have used max_workers=1 to have just one additional thread other
        # than the main thread. The reason for this is that Python Global
        # Interpreter Lock would not allow true multi-threading of CPU
        # intensive threads. The threading here just lets the python main
        # thread read the next chunk of log lines while the thread is processing
        # the previous chunk. Python 3.13 makes GIL optional, so increasing
        # max_workers might result in enhanced performance there.

        self.log("Starting flow logs analysis ..")
        with open(
                self.flowlogs,
                mode='r') as handle, ThreadPoolExecutor(max_workers=1) as executor:
            while True:
                lines = list(islice(handle, CHUNK_SIZE))
                if not len(lines):
                    break
                executor.submit(self._analyze_flow_logs, lines)

        if DEBUG:
            for key, value in self.tag_count.items():
                print(key, value)
            for key, value in self.combinations_count.items():
                print(key[0], key[1], value)

        self._write_output_file()

    def _write_output_file(self):
        if not self.outputfile:
            return

        self.log("Writing output file ..")
        with open(self.outputfile, 'w') as handle:
            handle.write(TAG_COUNT_FH)
            for key, value in self.tag_count.items():
                handle.write("{} {}\n".format(key, value))

            handle.write(COMB_COUNT_FH)
            for key, value in self.combinations_count.items():
                handle.write("{} {} {}\n".format(key[0], key[1], value))


class DefaultFlowLogsParser(GenericFlowLogParser):
    """ Class representing a flowlog parser object for default (2) version.

        Implements the following methods:
        1. _analyze_flow_logs()

    """

    def __init__(self,
                 version,
                 logs,
                 mappings,
                 output,
                 proto_map_file=None,
                 logger=None):
        super().__init__(version, logs, mappings, output, proto_map_file,
                         logger)
        self.errors = 0

    def _analyze_flow_logs(self, lines):
        self.log("Analyzing version {} logs ..".format(self.version))

        # Implementation Note:
        # I have used a lock here, even though the max_workers is set to 1.
        # This is for future compatibility.

        with self.counts_lock:
            for line in lines:
                fields = line.strip().split()
                if len(fields) < V2_FIELDS_COUNT:
                    self.errors += 1
                    continue

                try:
                    dstport = fields[V2_DST_PORT_IDX]
                    protocol_name = self.table[int(fields[V2_PROTO_NUM_IDX])]

                    # Implementation Note:
                    # In Python one can use a set as a key in a dictionary. I
                    # have made use of this facility to help map (port, protocol)
                    # to the tag provided in the mapfile.
                    #
                    # In programming languages that do not support this, I would
                    # implement binary serach tree based lookup where the tree
                    # nodes contain a list of protocols that can be mapped to
                    # that port and the associated tag. Thus processing using
                    # this tree structure would require an O(log(n)) lookup
                    # (vs O(1) here) to find the tag that a particular port
                    # using binary search, protocol combination needs to be
                    # mapped to.
                    #
                    # Following is a sample C structure for the same tree node:
                    #
                    # typedef struct treenode {
                    #   unsigned short port_num;
                    #   protocol_list_t *head;
                    # } treenode_t;
                    #
                    # tyepedef struct protocol_list_t {
                    #   char *protocol_name;
                    #   char *tag;
                    # } protocol_list_t;
                    #

                    key = (int(dstport), protocol_name.lower())

                    if key in self.tag_map.keys():
                        self.tag_count[self.tag_map[key]] += 1
                    else:
                        self.tag_count['Untagged'] += 1

                    self.combinations_count[key] += 1
                except (ValueError, IndexError):
                    self.errors += 1
        self.log("Total errors: {}".format(self.errors))


class CustomFlowLogsParser(GenericFlowLogParser):
    """ Class representing a flowlog parser object for custom version

        The following methods need to be implmented for specific log
        fields analysis:
        1. _analyze_flow_logs()

    """

    def __init__(self,
                 version,
                 logs,
                 mappings,
                 output,
                 proto_map_file=None,
                 logger=None):
        super().__init__(version, logs, mappings, output, proto_map_file,
                         logger)

    def _analyze_flow_logs(self, lines):
        pass
