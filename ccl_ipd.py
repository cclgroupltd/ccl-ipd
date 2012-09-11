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

import sys
import os
from struct import unpack

__version__ = "1.0"
__description__ = "Parse Blackberry IPD File"
__contact__ = "acaithness@ccl-forensics.com"


# A bit of convenience to keep code clearer down below...
def __decode_record__(record_data, record_obj):
    fields = []
    offset = 0

    while (offset < len(record_data)):
        # Decode data
        field_len, = unpack("<H", record_data[offset:offset + 2])
        offset += 2

        field_typ = record_data[offset]
        offset += 1

        field_dat = record_data[offset:offset + field_len]
        offset += field_len

        # add to the record
        record_obj.add_field(ipd_field(field_typ, field_dat))

class ipd_field:
    """
    Represents a field in an IPD record
    """
    def __init__(self, field_type, data):
        """
        Constructor: takes the field type number and the field data as arguments.

        Ideally this constructor should only be called from inside ccl_ipd.ipd_file's 
        constructor.
        """
        self.field_type = field_type
        self.field_data = data
    
    def __repr__(self):
        return "Field type: {0}; Data: {1}".format(self.field_type,self.field_data)

    def __str__(self):
        return self.__repr__()

class ipd_record:
    """
    Represents a record in an IPD databse.
    """
    def __init__(self, db_version, db_handle, record_id):
        """
        Constructor: takes the database version, handle and record ID as arguments.
        This initialises the record contain no fields.

        Ideally this constructor should only be called from inside ccl_ipd.ipd_file's 
        constructor.
        """
        self.db_version = db_version
        self.db_handle = db_handle
        self.record_id = record_id
        self.fields = []
        pass

    def add_field(self, field):
        """
        Adds a field to this record
        """
        if not isinstance(field, ipd_field):
            raise TypeError("\"field\" must be a ccl_ipd.ipd_field.")
        self.fields.append(field)

    def __getitem__(self, item):
        return self.fields[item]

    def __iter__(self):
        """
        Returns an iterator for fields in this record.
        """
        return self.fields.__iter__()

    def __repr__(self):
        return "Record Id: {0}; Record Data:{1}".format(self.record_id,
                                                           "\n\t\t".join([repr(f) for f in self.fields]))
    def __str__(self):
        return self.__repr__()

class ipd_db:
    """
    Represents a single named database in an IPD file.
    """
    def __init__(self, db_name):
        """
        Constructor: takes the database name as an argument. This initialises
        the object containing no records.

        Ideally this constructor should only be called from inside ccl_ipd.ipd_file's 
        constructor.
        """
        self.db_name = db_name
        self.records = []

    def add_record(self, record):
        """
        Adds a record to this database object.
        """
        if not isinstance(record, ipd_record):
            raise TypeError("\"record\" must be a ccl_ipd.ipd_record")
        self.records.append(record)

# Need to give some design thought as to whether these should be provided
# as methods or not. Not sure how it applies here. The record number doesn't
# have to be unique so I'm not sure how useful this is. Simple to implement
# if required. "records" is public regardless.
#    def __getitem__(self, item):
#        return self.records[item]

#    def __contains__(self, item):
#        # to add in support
#        pass

    def __iter__(self):
        """
        Returns an iterator for the records in this database.
        """
        return self.records.__iter__()

    def __repr__(self):
        return "Database Name: {0}; Records:{1}".format(self.db_name,
                                                        "\n\t".join([repr(r) for r in self.records]))

    def __str__(self):
        return self.__repr__()

class ipd_file:
    """
    Represents a Blackberry IPD file.
    The object is subscriptable based on database name and iterable.
    """
    def __init__(self, file_name):
        """
        Constructor: takes the file path of the IPD file. Populates the object
        with the data foundin the IPD file.
        """
        # Get file size and open file.
        fileSize = os.path.getsize(file_name)
        f = open(file_name, "rb")

        # Skip the header and start reading details
        f.seek(38)

        # Get the metadata and database names
        self._database_version_ = f.read(1)
        self._number_of_databases_, = unpack(">h", f.read(2))

        f.read(1) # skip the nul

        database_names    = []
        self.databases  = {} # Dictionary of databases

        for i in range(self._number_of_databases_):
            database_name_length, = unpack("<h", f.read(2))
            database_name = f.read(database_name_length).decode()[:-1] # remove nul term
            database_names.append(database_name)
            self.databases[database_name] = ipd_db(database_name)
         
        # Now we read the data...
        while f.tell() < fileSize:
            database_ref = unpack("<H", f.read(2))[0]
            if database_ref == 65535: break

            record_length = unpack("<I", f.read(4))[0]

            record_data = f.read(record_length)

            offset = 0

            database_version = record_data[offset]
            offset += 1

            database_handle  = unpack('<H', record_data[offset:offset+2])[0]
            offset += 2

            record_id = unpack('<I', record_data[offset:offset+4])[0]
            offset += 4

            # create our record object and populate it with fields
            this_record = ipd_record(database_version, database_handle, record_id)
            __decode_record__(record_data[offset:], this_record)

            # get the database object. The database_ref refers to the index of the 
            # database name at the start of the file

            this_db = self.databases[database_names[database_ref]]
            this_db.add_record(this_record)

    def __getitem__(self, item):
        """
        Returns the ccl_ipd.ipd_db object named as "item".
        """
        if item in self.databases:
            return self.databases[item]
        else:
            raise KeyError("Database {0} not found in this IPD".format(item))

    def __contains__(self, item):
        """
        Returns True if an ipd_db named "item" is in this ipd_file
        """
        return item in self.databases

    def __iter__(self):
        """
        Returns an iterator for the ipd_db objects in the ipd_file
        """
        return self.databases.values().__iter__()

    def __repr__(self):
        return str(self.databases)

    def __str__(self):
        return self.__repr__()
