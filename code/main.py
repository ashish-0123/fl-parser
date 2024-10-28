#!/usr/bin/env python3

import logging
from flowlog_parser import *

def main():
    logging.basicConfig(
        filename="../files/log.txt",
        filemode='a',
        format='%(asctime)s,%(msecs)d %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
        level=logging.INFO)
    logger = logging.getLogger()
    try:
        fl = DefaultFlowLogsParser(2,
                                   "../files/biglogs.txt",
                                   "../files/empty.csv",
                                   "../files/output.txt",
                                   proto_map_file="../files/protocol-numbers-1.csv",
                                   logger=logger)
        fl.read_mappings_file()
        fl.read_proto_mappings()
        fl.analyze_flow_logs()
    except FlowLogParserException as e:
        print("[ERROR] - ", str(e))


if __name__ == "__main__":
    main()
