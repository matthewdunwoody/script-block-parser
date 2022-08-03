#   Copyright 2016, Matthew Dunwoody
#   dunwoody.matthew@gmail.com
#   @matthewdunwoody
#
#   Built on Willi Ballenthin's Python-EVTX https://github.com/williballenthin/python-evtx
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version 1.0
import os
from re import I
import sys
import argparse
import traceback
from typing import Generator, Iterable
from collections import defaultdict

from lxml import etree

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view


def to_lxml(record_xml):
    """
    @type record: Record
    """
    try:
        return etree.fromstring(
            '<?xml version="1.0" standalone="yes" ?>%s'
            % record_xml.replace(
                'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', ""
            )
        )
    except:
        return etree.fromstring(
            '<?xml version="1.0" standalone="yes" ?>%s'
            % record_xml.replace(
                'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', ""
            )
        )


class ScriptBlockEntry(object):
    def __init__(
        self,
        level,
        computer,
        timestamp,
        message_number,
        message_total,
        script_block_id,
        script_block_text,
    ):
        super(ScriptBlockEntry, self).__init__()
        self.level = level
        self.computer = computer
        self.timestamp = timestamp
        self.message_number = message_number
        self.message_total = message_total
        self.script_block_id = script_block_id
        self.script_block_text = script_block_text

    def get_metadata(self):
        return (
            self.script_block_id
            + ","
            + str(self.timestamp)
            + ","
            + str(self.level)
            + ","
            + str(self.message_total)
            + ","
            + self.computer
            + ","
            + str(self.message_number)
        )


class Entry(object):
    def __init__(self, xml, record):
        super(Entry, self).__init__()
        self._xml = xml
        self._record = record
        self._node = to_lxml(self._xml)

    def get_xpath(self, path):
        return self._node.xpath(path)[0]

    def get_eid(self):
        return int(self.get_xpath("/Event/System/EventID").text)

    def get_script_block_entry(self):
        level = int(self.get_xpath("/Event/System/Level").text)
        computer = self.get_xpath("/Event/System/Computer").text
        timestamp = self._record.timestamp()
        message_number = int(
            self.get_xpath("/Event/EventData/Data[@Name='MessageNumber']").text
        )
        message_total = int(
            self.get_xpath("/Event/EventData/Data[@Name='MessageTotal']").text
        )
        script_block_id = self.get_xpath(
            "/Event/EventData/Data[@Name='ScriptBlockId']"
        ).text
        script_block_text = self.get_xpath(
            "/Event/EventData/Data[@Name='ScriptBlockText']"
        ).text
        return ScriptBlockEntry(
            level,
            computer,
            timestamp,
            message_number,
            message_total,
            script_block_id,
            script_block_text,
        )


def get_entries(evtx):
    """
    @rtype: generator of Entry
    """
    try:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield Entry(xml, record)
            except:
                traceback.print_exc()
    except:
        yield None


def get_entries_with_matching_event_ids(
    evtx: str, event_ids: Iterable
) -> Generator[Entry, None, None]:
    """
    @type eids: iterable of int
    @rtype: generator of Entry
    """
    for entry in get_entries(evtx):
        try:
            if entry and entry.get_eid() in event_ids:
                yield entry
        except:
            continue


def process_entries(
    entries: list[Entry],
    script_id: str,
    all_blocks: bool,
    output_dir: str,
    filename: str,
    output_to_csv: bool,
):
    blocks = defaultdict(list)
    metadata = {}

    for entry in entries:
        script_block_entry = entry.get_script_block_entry()
        if script_id == script_block_entry.script_block_id or (
            (all_blocks or script_block_entry.message_total > 1) and script_id == None
        ):
            blocks[script_block_entry.script_block_id].insert(
                script_block_entry.message_number,
                script_block_entry.script_block_text.replace("&lt;", ">").replace(
                    "&gt;", "<"
                ),
            )
            if script_block_entry.script_block_id not in metadata:
                metadata[script_block_entry.script_block_id] = script_block_entry

    output_result(blocks, metadata, output_dir, filename, output_to_csv)


def output_result(
    blocks: defaultdict[list],
    metadata: dict,
    output_dir: str,
    output_file: str,
    output_to_csv: bool,
):
    divider = "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
    header = "Script Block ID,Timestamp,Level,Path,Message Total,Computer,First Message Number"

    if blocks:
        if output_file:
            if not os.path.isdir(os.path.abspath(os.path.dirname(output_file))):
                os.makedirs(os.path.dirname(output_file))

            with open(output_file, "w") as f:
                keys = blocks.keys()
                for script_block_id in keys:
                    if metadata[script_block_id].message_number > 1:
                        x = " -partial"
                    else:
                        x = ""
                    f.write(
                        divider
                        + metadata[script_block_id].script_block_id
                        + x
                        + divider
                    )
                    f.write("".join(blocks[script_block_id]))
        elif output_dir:
            # output_dir = output_dir.replace("\\\\", "\\")
            print(output_dir)
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir)
            keys = blocks.keys()
            for script_block_id in keys:
                if metadata[script_block_id].message_number > 1:
                    x = "-partial"
                else:
                    x = ""
                f = open(os.path.join(output_dir, script_block_id + x + ".ps1_"), "w")
                f.write("".join(blocks[script_block_id]))
                f.close()

        if output_to_csv:
            if not os.path.isdir(os.path.abspath(os.path.dirname(output_to_csv))):
                os.makedirs(os.path.dirname(output_to_csv))
            f = open(output_to_csv, "w")
            f.write(header)
            keys = blocks.keys()
            for script_block_id in keys:
                f.write("\n" + metadata[script_block_id].get_metadata())
            f.close()

    else:
        print("No blocks found")


def main():
    parser = argparse.ArgumentParser(
        description="Parse PowerShell script block log entries (EID 4104) out of the Microsoft-Windows-PowerShell%4Operational.evtx event log. By default, reconstructs all multi-message blocks."
    )
    parser.add_argument(
        "evtx",
        type=str,
        help="Path to the Microsoft-Windows-PowerShell%%4Operational.evtx event log file to parse",
    )
    parser.add_argument(
        "-m",
        "--metadata",
        type=str,
        help="Output script block metadata to CSV. Specify output file.",
    )
    parser.add_argument(
        "-s", "--scriptid", type=str, help="Script block ID to parse. Use with -f or -o"
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Write blocks to a single file. Specify output file.",
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=str,
        help="Output directory for script blocks as ps1 files.",
    )
    parser.add_argument("-a", "--all", action="store_true", help="Output all blocks.")
    args = parser.parse_args()

    if not (args.file or args.outdir):
        parser.error(
            "Output format required. Use -f to write all blocks to a single file, or -o to output all blocks as .ps1 files in the specified directory."
        )
    print(args.outdir)
    with Evtx(args.evtx) as evtx:
        process_entries(
            get_entries_with_matching_event_ids(evtx, set([4104])),
            args.scriptid,
            args.all,
            args.outdir,
            args.file,
            args.metadata,
        )
        pass


if __name__ == "__main__":
    main()
