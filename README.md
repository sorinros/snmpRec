# snmpRec
snmpRec, C++ front end for net-SNMP

The snmpRec library is part of the Network Access Control application called NACmgr.  It was written by Paige Stafford for Oak Ridge National Laboratory when the lab was building its own services.

snmpRec requires these libraries
o. Net-SNMP library (http://www.net-snmp.org), using flag -lsnmp.

o. pThreads: POSIX threaded library, using flag -lphread

o. libnsl (the network services library), using -lnsl


