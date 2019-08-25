#!/usr/bin/env python3

import json
import argparse
import sys
import os.path as path
import re
import urllib.request as request
from collections import defaultdict
import subprocess
from xml.etree import ElementTree as ET

data_url = "https://software.intel.com/sites/landingpage/IntrinsicsGuide/files/data-latest.xml"

def find_command(cmd, root):
    all_matches = root.findall("./intrinsic/instruction[@name='%s']/.." % cmd)
    for intrinsic in all_matches:
        func_name = intrinsic.get("name")
        cpuid = intrinsic.get("tech")
        print("%s => %s => %s" % (cpuid, cmd, func_name))

def find_ops_by_objdump(executable):
    found_ops = set()
    out = subprocess.check_output(["objdump", "-M", "intel", "--no-show-raw-insn", "-D", executable])
    for line in out.decode(encoding='utf-8').split("\n"):
        line = line.split()
        if len(line) < 3:
            continue
        op = line[1]
        found_ops.add(op)
    return found_ops

def extract_info_of_ops(found_ops, root):
    found_features = set()
    for op in found_ops:
        all_matches = root.findall("./intrinsic/instruction[@name='%s']/.." % op)
        all_matched_cpuid = set()
        for intrinsic in all_matches:
            cpuid = intrinsic.get("tech")
            cpuid_info = (cpuid, op)
            all_matched_cpuid.add(cpuid_info)
        found_features.update(all_matched_cpuid)

    return found_features
        
if __name__ == '__main__':
    own_path = path.dirname(sys.argv[0])
    parser = argparse.ArgumentParser(description="Tries to detect which CPU "
        "features where used in a given binary.")
    parser.add_argument("-m", "--xml-data-file", default=str(path.join(own_path, "data-latest.xml")),
        required=False, help="xml file containing intel instructions.")
    parser.add_argument("-d", "--show-details", action="store_true", required=False, 
        default = False, help="Show instructions of CPUID in output.")
    parser.add_argument("-b", "--include-base", action="store_true", required=False, 
        help="Include base instructions in the search.")
    parser.add_argument("-l", "--lookup-op", action="store_true", required=False, 
        help="Lookup CPU ID for a given command.")
    parser.add_argument("executable", help="The executable to analyze or the "
        "command to lookup if -l is set.")
    args = parser.parse_args()
    
    
    root = None
    # Parse xml data of intel instructions
    if path.isfile(args.xml_data_file):
        try:
            root = ET.parse(args.xml_data_file).getroot()
        except Exception as e:
            print("Failed to parse data from '%s'" % args.xml_data_file)
            print(e)
            exit(1)
    else:
    # Dowload intel instructions
        try:
            print("Downloading file from %s" % data_url)
            resp = request.urlopen(data_url)
            data_xml = resp.read()
            with open(args.xml_data_file, "wb") as fp:
                fp.write(data_xml)
            root = ET.parse(args.xml_data_file).getroot()
        except Exception as e:
            print("Failed to download file from '%s'" % data_url)
            print(e)
            exit(1)
    
    # Lookup CPUID for a given command
    if args.lookup_op:
        find_command(args.executable, root)
        exit(0)
    
    print("Running objdump")
    found_ops = find_ops_by_objdump(args.executable)
    
    print("Found %i ops" % len(found_ops))
    found_features = extract_info_of_ops(found_ops, root)

    foo = defaultdict(list)
    for cpuid, op in found_features:
        foo[cpuid].append(op)
    for cpuid in foo:
        avx512 = re.compile("AVX-512.*")
        if (avx512.match(cpuid)):
            continue
        print("- %s" % cpuid)
        if (args.show_details):
            for op in foo[cpuid]:
                print("\t- %s" % op)