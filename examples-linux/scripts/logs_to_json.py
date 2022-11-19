"""
Copyright (c) 2021, Nils Rothaug
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived
from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import sys
import argparse

parser = argparse.ArgumentParser(description='Reads logs from stdin, writes them to file in a json compatible format and prints the input')
parser.add_argument("logfile", help="Name of the JSON file to store logs in", type=str)
args = parser.parse_args()

# Don' trip on weird input
sys.stdin.reconfigure(errors="ignore")

with open(args.logfile, 'x') as file:
    log_started = False
    endof_json = 0

    for line in sys.stdin:
        print(line, end='')

        # Do not write none JSON tunslip output to file
        if (not log_started) and line.startswith("{"):
            file.write("[\n")
            log_started = True

        if log_started:
            file.write("\t" + line)
            if "}," in line:
                endof_json = file.tell()

    # Delete last lines that do not contain JSON logs (but tunslip crashing after ^C)
    file.seek(endof_json)
    file.truncate()
    # And write footer
    file.write("\t{\n\t\t\"type\": \"end\"\n\t}\n]")