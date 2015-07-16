#ifndef SNMPREC_H
#define SNMPREC_H

extern bool DEBUG, SILENT;

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/session_api.h>

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>


#define SNMP_SET_OIDS netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT, NETSNMP_OID_OUTPUT_NUMERIC)
#define SNMP_SET_LIBS netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM, 1)
#define SNMP_SET_QKPR netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 0)


#define NETSNMP_DS_WALK_INCLUDE_REQUESTED       1
#define NETSNMP_DS_WALK_PRINT_STATISTICS        2
#define NETSNMP_DS_WALK_DONT_CHECK_LEXICOGRAPHIC        3
#define NETSNMP_DS_LIB_PRINT_HEX_TEXT           23

#include <net-snmp/net-snmp-includes.h>

#include <iostream>
#include <string>

using namespace __gnu_cxx;
#include <ext/hash_map>
#include <hash_map>
#include <map>

#define VLANS 63
#define IFINDEX_TO_IFNAME 0
#define PORTNUM_TO_IFINDEX 1
#define PORTINDEX_TO_PORTNUM 2
#define PORTINDEX_TO_MAC 3
#define ARP 4
#define SYS_DESCR 5
#define SYSTEM_NAME 6
#define IFDESCR 7
#define IF_STATUS 8
#define IFENTRY 9
#define CDP 10
#define NEIGHBORDISCOVERY 11

#define _3COM_ 1
#define _FOUNDRY_ 2
#define _AP_ 3
#define _CISCO_ 50
#define _C2948_ 51
#define _C2950_ 52
#define _C2960_ 53
#define _C2970_ 54
#define _C3750_ 55
#define _C3750_2_ 62
#define _CAT4000_ 56
#define _C2980_ 57
#define _C6509_ 58
#define _VRF_ 70

#define _FW_ 67
#define _FW_W_SWITCHES_ 99
#define _OUTSIDE_FW_ 67
#define _INSIDE_FW_ 68
#define _CASA5520_FW_ 68
#define _NEXUS_VDC_ 81
#define _NEXUS_ 63
#define _NEXUS_NO_SSH_ 72
#define _CISCO_NO_SSH_ 66


using namespace std;

#include "fmt.hpp"

typedef map<string, int> map_t;

typedef struct arp_record_t {
    bool L2_found;
    string ip;
    string mac;
    string vlan;
    map_t ips; //marker
} arp_record_t;

unsigned int orig_Hash(const string& str);

class stringhasher {
public:
  size_t operator() (const string& s) const { return (size_t) orig_Hash(s); }
  bool operator() (const string& s1, const string& s2) const { return s1 < s2; }
};

// compares two lists of type <string, int>
extern bool same_map(map_t m1, map_t m2);
extern void send_error(string msg);


class polling_record
{
  public:
    string mac;
    string ifName;
    string portNum;
    string vlan;
    string L2_vlan;
    unsigned int vlan_id;
    string vlan_name;
    string L2;
    string L3;
    string dt1;
    string dt2;
    map_t ips;
    unsigned int id;
    unsigned int L2_id;

    bool needs_scan(string last_timestamp);
    void print_poll_record();

    // if(new != old) -- rhs is the old
    bool operator!=(const polling_record &rhs) const
    {
        if(mac != rhs.mac ) {
            if(DEBUG) cout << "\tMAC is Different: " << mac << " vs " << rhs.mac << "\n";
            return true;
        }
        if( ifName != rhs.ifName ) {
            if(DEBUG) cout << "\tifName is Different: " << mac <<"\n";
            return true;
        }
        if( L2 != rhs.L2 ) {
            if(DEBUG) cout << "\tL2 is Different: '" << L2 << "' '" << rhs.L2 << "': " << mac <<"\n";
            return true;
        }
        if( vlan != rhs.vlan ) {
            if(DEBUG) cout << "\tvlan is Different: '" << vlan << "' '" << rhs.vlan << "': " << mac <<"\n";
            return true;
        }
        if( vlan != rhs.vlan ) {
            if(DEBUG) cout << "\tvlan is Different: '" << vlan << "' '" << rhs.vlan << "': " << mac <<"\n";
            return true;
        }

        if(!same_map(ips, rhs.ips) ) {
            if(DEBUG) cout << "\tIPS list is Different: : " << mac <<"\n";
            return true;
        }

        else if(DEBUG) cout << "IPs list is the same\n";

        if(DEBUG) cout << "\tpolling records are the same: " << mac <<"\n";
        return false;
  }
};



typedef struct sys_t {
    string ip;
    string subnet;
    int vlan_id;
    int sysType;
    string comm;
    string L3;
    string ipv6_ready;
    map_t vlans;
    string vlan;
    map_t IgnorePorts;
    hash_map<string, arp_record_t *, stringhasher>  A;
    vector<polling_record *> P;
    string d1, d2;
} sys_t;

typedef hash_map<string, string *, stringhasher> walkRecord_t;
typedef hash_map<string, polling_record *, stringhasher> pList_t;

extern unsigned int NAC_THREADS;

typedef struct vlan_P_rec {
    sys_t *rec;
    walkRecord_t *h0;
    walkRecord_t *portMapping;
    string vlan;
} vlan_P_rec;



class snmpRec
{
  pthread_cond_t snmp_cond;
  pthread_mutex_t snmp_mutex;
  bool in_session;

  bool format_records(unsigned int oid_choice, string *s1, string *s2);
  void format_value(string *v);

  void format_index_1(string *i);
  void format_mac(string *s2);
  void format_arp_index(string *i);
  int get_Value(u_char ** buf, const netsnmp_variable_list * var);
  bool get_record(const oid * objid, size_t objidlen, const netsnmp_variable_list * variable, char *n, char *v);
  bool update_oid(unsigned int oid_choice, oid *r, size_t *len);

  public:

  bool format_port(string *p);

  string current_timestamp;
  snmpRec() { init_snmp_session(); }
  ~snmpRec() { SOCK_CLEANUP; }
  void format_indices(string *s2, unsigned int oid_choice);
  bool update_comm(void *, string);
  void *get_session(const char *, const char *);
  int getWalk(unsigned int oid_choice, const char *cString, const char *peername, walkRecord_t *);
  void init_snmp_session();
  string snmp_get(unsigned int oid_choice, char *cString, char *peername);
  bool get_ifIndex(string ip, string comm, string port, string *if_index);


  int get_vlans_from_list(walkRecord_t List1, walkRecord_t *vlans, const int type);
  void get_arp(sys_t *L3sys);
  void get_3com_bridge(string ip, string L3, string comm, vector<polling_record *> *P, map_t ports);
  void get_bridge(sys_t *rec);
  int return_sysType_id(string theS);
  void format_cdp_string(string index, string *v2);
  void format_if_status(string *v2);
  void format_neighbors(string *s1, string *s2);
  int get_sysType(string ip, string comm);
  bool get_L3_VLANS(walkRecord_t *, sys_t *);
  map_t *get_if_status_for_switch(string L2, string comm);
  bool get_cdp(string L2, string comm);
  unsigned int get_IF_indexes(sys_t *rec, walkRecord_t *h0);
  void *get_vlan_polling_data(void *v);
  bool is_IF_up(string ip, string comm, string port);
  bool block_port( string ip, string comm, string rw_comm, string port, char type, string *errorBuffer);
  int snmpset_do(int, char *[]);
  bool get_L2_ports_status(string ip, string comm, map_t *L2_ports);
  bool get_VLANS(map_t *vlans, string ip, string comm);

};


#endif
