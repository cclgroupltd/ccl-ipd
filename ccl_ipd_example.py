#!/usr/bin/env python3

"""
Copyright (c) 2011, CCL Forensics
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the CCL Forensics nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CCL FORENSICS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

# This example shows how to use the ipd_ccl module. The example we will use is
# extracting the installed application data from the "Handset Agent" database.
# This is not intended to be a complete and functioning script, but it should
# demonstrate the principals.

import sys
import ccl_ipd

# First step is to open the IPD file. We can just grab the file name at the command
# line.
ipd = ccl_ipd.ipd_file(sys.argv[1])

# It's a good idea to check that you actually have the database you require before 
# we start. The ipd_file class supports the "in" statement.
if "Handheld Agent" not in ipd:
    print("The Handheld Agent database is not present in the IPD file")
    exit()

# We can access the database by using the database name as the key:
db = ipd["Handheld Agent"]

# We can then iterate through the records in the database using for:
for record in db:
    # First step, the field with type 100 tells us what sort of application we're
    # looking at.
    type_code = None
    for field in record.fields:
        if field.field_type == 100:
            type_code = field.field_data[0]
            break
    if not type_code:
        raise KeyError("Type 100 not found in record.")
    
    # We are only interested in types 1 and 2 for the purposes of this script so we
    # can skip all others.
    if type_code not in (1,2):
        continue

    # Types 1 and 2 have slightly different layouts, so we deal with them separately
    module_name = ""
    module_vers = ""
    module_desc = ""
    if type_code == 1:
        for field in record.fields:
            if field.field_type == 2:
                # The field_data is a bytes object so  we need to decode to a string.
                module_name = field.field_data.decode() 
            elif field.field_type == 3:
                module_vers = field.field_data.decode()
    elif type_code == 2:
        for field in record.fields:
            if field.field_type == 2:
                module_name = field.field_data.decode()
            elif field.field_type == 4:
                module_desc = field.field_data.decode()

    
    # And output to the console (in a tsv format)
    print("\t".join([module_name, module_vers, module_desc]))


