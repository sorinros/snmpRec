/* snmpRec.cpp
 * Written by Paige Stafford, 2015
 */


#include "snmpRec.hpp"
typedef map<string, int> map_t;
typedef hash_map<string, string *, stringhasher> walkRecord_t;
typedef hash_map<string, polling_record *, stringhasher> pList_t;
typedef hash_map<string, arp_record_t *, stringhasher> aList_t;

extern bool SILENT, DEBUG;

void snmpComment(string the_string)
{
  if(SILENT) return;
  if(DEBUG==false) return;
  cout << the_string << "\n";
  fflush(stdout);
}


unsigned int orig_Hash(const string& str)
{
    size_t h = 0;
    string::const_iterator p, p_end;
    for(p = str.begin(), p_end = str.end(); p != p_end; ++p) { h = 31 * h + (*p); }
    return h;
}

//------------------------------------------------------------------------
void polling_record::print_poll_record()
{
  if(SILENT) return;

  fprintf(stderr, "%s\t%s\t", mac.c_str(),ifName.c_str());

  for(map_t::iterator m=ips.begin(); m != ips.end(); m++) {
      if( m!=ips.begin()) fprintf(stderr, ",");
      fprintf(stderr, "%s", (m->first).c_str());
  }
  fprintf(stderr, "\t%s\t%s\t%s\n", L2.c_str(), vlan.c_str(), L3.c_str());
  fflush(stderr);
}

//-------------------------------------------------
bool polling_record::needs_scan(string s2)
{
  if(dt2.length() == 0) {
      if(!SILENT) cout << "ERROR (needs_scan()): dt2 is empty!\n";
      return false;
  }
  if(s2.length() == 0) {
      if(!SILENT) cout << "ERROR (needs_scan()): s2 is empty!\n";
      return false;
  }

  uint current_year = (uint) atoi( (dt2.substr(0,4)).c_str());
  uint prev_year = (uint) atoi( (s2.substr(0,4)).c_str());

  if(current_year < prev_year) {
      if(!SILENT) cout << mac << "\tcurrent_year < prev_year -- returning false (" << s2 << ", " << dt2 << ")\n";
      return false;
  }

  uint total_days[13]; total_days[0]=0; total_days[1]=31; total_days[2]=28; total_days[3]=31;
  total_days[4]=30; total_days[5]=31; total_days[6]=30; total_days[7]=31; total_days[8]=31;
  total_days[9]=30; total_days[10]=31; total_days[11]=30; total_days[12]=31;

  uint current_month    = (uint) atoi( (dt2.substr(5,2)).c_str());
  uint prev_month       = (uint) atoi( (s2.substr(5,2)).c_str());
  uint current_day      = (uint) atoi( (dt2.substr(8,2)).c_str());
  uint prev_day         = (uint) atoi( (s2.substr(8,2)).c_str());
  uint current_hour     = (uint) atoi( (dt2.substr(11,2)).c_str());
  uint prev_hour        = (uint) atoi( (s2.substr(11,2)).c_str());
  uint current_minutes  = (uint) atoi( (dt2.substr(14,2)).c_str());
  uint prev_minutes     = (uint) atoi( (s2.substr(14,2)).c_str());

  uint days_diff, hours_diff, month_diff;

  if(current_year > prev_year) month_diff = (12-prev_month) + current_month;
  else month_diff = current_month - prev_month;

  if( month_diff > 1 ) {
      if(!SILENT) cout << mac << "\tmonth_diff > 1 -- returning true (" << s2 << ", " << dt2 << ")\n";
      return true;
  }
  else if( month_diff == 1) days_diff = total_days[prev_month] - prev_day + current_day;
  else days_diff = current_day - prev_day;


  if( days_diff > 1) {
      if(!SILENT) {
          cout << mac << "\tyear_greater , month_diff<=1, and days_diff > 1 -- returning true ("
               << s2 << ", " << dt2 << ")\n";
      }
      return true;
  }
  else if( days_diff == 1) hours_diff = (24-prev_hour) + current_hour;
  else hours_diff = current_hour - prev_hour;

  if( hours_diff > 4) {
      if(!SILENT) cout << mac << "\thours are > 4 returning true (" << s2 << ", " << dt2 << ")\n";
      return true;
  }
  else if( hours_diff == 4 ) {
      if(current_minutes >= prev_minutes) {
          if(!SILENT) cout << mac << "\thours==4+ -- returning true (" << s2 << ", " << dt2 << ")\n";
          return true;
      }
      return false;
  }
  return false;
}

// compares two lists of type <string, int>
// referenced by include/snmpRec.hpp
//------------------------------------------------------
bool same_map(map_t the_map, map_t orig)
{
   map_t::iterator m;

  //  To prevent the lack of TCP/IP traffic from getting archived,
  //  will assume that last IP address seen was what was being used.
  // PST commenting this out 8/20/2010
  //if(the_map.size()==0) return true;

  // if list sizes are not the same, return false
  if(the_map.size() != orig.size()) {
      snmpComment("\tsame_map():: List Sizes are different");
      return false;
  }

  // so, now we know that
  // the list sizes are the same

  // return if the lists are empty (if one is empty, so is the other)
  if(the_map.size() == 0) {
      if(DEBUG) cout << "\tsame_map():: the_map is empty\n";
      return true;
  }

  // initialize list2's values to 1
  if(DEBUG) {
      for(m = the_map.begin();  m != the_map.end(); m++) {
          cout << "1map: " << m->first << " :: " << m->second << "\n";
      }
      for(m = orig.begin();  m != orig.end(); m++) {
          cout << "2map: " << m->first << " :: " << m->second << "\n";
      }
  }


  // see if every member of list 1 is in list 2 -- if not found, return false
  for(m = the_map.begin();  m != the_map.end(); m++)
  {
      if(DEBUG) cout << "checking new list item: " << m->first << "\n";

      map_t::iterator id = orig.find(m->first);
      if(id == orig.end()) {
          if(DEBUG) cout << "\t" << m->first << " -- NOT found in the original IP List\n";
          return false;
      }
      // Have the same list object -->map1[objectA]=value?, map2[objectA]=value?.
      // Now, need to compare values.
      if(id->second != m->second)  return false;
  }

  for(m = orig.begin();  m != orig.end(); m++)
  {
      map_t::iterator id = the_map.find(m->first);
      if(id == the_map.end()) {
          if(DEBUG) cout << "\t" << m->first << " -- NOT found in the new IP List\n";
          return false;
      }
      // Have the same list object -->map1[objectA]=value?, map2[objectA]=value?.
      // Now, need to compare values.
      if(id->second != m->second) return false;
  }
  return true;
}

//----------------------------------------------------------------------------
bool snmpRec::format_port(string *p)
{
  fmt f;
  if(p==0 || p->size()==0) return false;

  *p = f.trim(*p);
  if(p->size()==0) return false;

  *p = f.fmt_lower(*p);

  if(p->find("encapsulation", 0) != string::npos) return false;
  if(p->find("unrouted", 0) != string::npos) return false;
  if(p->find("null0", 0) != string::npos) return false;
  if(p->find("stacksub", 0) != string::npos) return false;

  string::size_type end;

  if(p->find("vlan", 0) == string::npos) {
      if( p->find("vl", 0) != string::npos)
      {
          end = p->find("vl", 0);
          p->erase(end, 2);
          if(p->size()==0) return false;
          string *newP = new string("Vlan" + *p);
          *p = *newP;
          return true;
      }

      // implied else
      if( p->at(0)=='v')
      {
      end = p->find("v", 0);
          if(p->size() <= 1) return false;
          p->erase(end, 1);
          string *newP = new string("Vlan" + *p);
          *p = *newP;
          return true;
      }
  }

  end = p->find(":v3", 0);
  if(end != string::npos) { p->erase(end, 3); }


  end = p->find("gigabitethernet", 0);
  if(end != string::npos) {
      string::size_type end2 = p->find("tengigabitethernet", 0);
      if(end2 != string::npos ) p->replace(end2, 18, "Te");
      else p->replace(end, 15, "Gi");
      return true;
  }

  else
  {
      end = p->find("fastethernet", 0);
      if(end != string::npos) p->replace(end, 12, "Fa");
      else
      {
          end = p->find("rmon", 0);
          if(end != string::npos)
          {
              p->erase(0, 4);
              if(p->size()==0) return false;

              if((*p)[0] == ':' || (*p)[0] == ' ') {
                  p->erase(0, 1);
                  if(p->size()==0) return false;
              }
              if( p->find("10/100 ", 0) != string::npos) {
                  p->erase(0, 6);
                  if(p->size()==0) return false;
              }
              else if( p->find("v3 ", 0) != string::npos || p->find("ge ", 0) != string::npos)  {
                  p->erase(0, 3);
                  if(p->size()==0) return false;
              }

              end = p->find("port ", 0);
              if(end != string::npos) { p->replace(end, 5, "p"); }
              else return false;

              end = p->find(" on unit ", 0);
              if(end != string::npos) {
                  p->replace(end, 9, "/u");
                  if(p->size()==0) return false;
              }
              else return false;

              // p21u3
              if(p->size()< 4) return false;
              *p = f.trim(*p);
              return true;
          }

          end = p->find("gi", 0);
          if(end != string::npos) p->replace(end, 1, "G");

          end = p->find("te", 0);
          if(end != string::npos) p->replace(end, 1, "T");

          end = p->find("fa", 0);
          if(end != string::npos) p->replace(end, 1, "F");

          end = p->find("ge", 0);
          if(end != string::npos) p->replace(end, 2, "Gi");

          end = p->find("ethernet", 0);
          if(end != string::npos) p->replace(end, 8, "eth");
      }
  }
  end = p->find("subif", 0);
  if(end != string::npos) {
      p->erase(end, 5);
      if(p->size()==0) return false;
  }
  end = p->find("utp", 0);
  if(end != string::npos) {
      p->erase(end, 3);
      if(p->size()==0) return false;
  }
 end = p->find("(", 0);
  if(end != string::npos) {
      p->erase(end, 1);
      if(p->size()==0) return false;
  }
  end = p->find(")", 0);
  if(end != string::npos) {
      p->erase(end, 1);
      if(p->size()==0) return false;
  }
  end = p->find("cat", 0);
  if(end != string::npos) {
      p->erase(end, 3);
      if(p->size()==0) return false;
  }
  end = p->find("rmon:", 0);
  if(end != string::npos) {
      p->erase(end, 5);
      if(p->size()==0) return false;
  }
  end = p->find("port", 0);
  if(end != string::npos) {
      p->erase(0, end+4);
      if(p->size()==0) return false;
  }
  end = p->find("on unit ", 0);
  if(end != string::npos) {
      p->erase(end-1, p->length());
      if(p->size()==0) return false;
  }

  return true;
}


//------------------------------------------
void snmpRec::format_indices(string *s2, uint oid_choice)
{
  switch(oid_choice) {
      case VLANS: {
          string::size_type end = s2->find(".1.3.6.1.2.1.47.1.2.1.1.2.", 0);
          //uint end = s2->find(".1.3.6.1.2.1.2.2.1.2.", 0);
          if(end != string::npos) s2->erase(end, 26);
          break;
      }
      case IFINDEX_TO_IFNAME: {
          string::size_type end = s2->find(".1.3.6.1.2.1.31.1.1.1.1.", 0);
          if(end != string::npos) s2->erase(end, 24);
          break;
      }
      case IFDESCR: {
          string::size_type end = s2->find(".1.3.6.1.2.1.2.2.1.2.", 0);
          if(end != string::npos) s2->erase(end, 21);
          break;
      }
      case IFENTRY: {
          string::size_type end = s2->find(".1.3.6.1.2.1.2.2.1.7.", 0);
          if(end != string::npos) s2->erase(end, 21);
          break;
      }
      case PORTNUM_TO_IFINDEX: {
          string::size_type end = s2->find(".1.3.6.1.2.1.17.1.4.1.2.", 0);
          if(end != string::npos) s2->erase(end, 24);
          break;
      }
      case ARP: {
          string::size_type end = s2->find(".1.3.6.1.2.1.4.22.1.2.", 0);  // ARP
          if(end != string::npos) s2->erase(end, 22);
          break;
      }
      case IF_STATUS: {
          string::size_type end = s2->find(".1.3.6.1.2.1.2.2.1.7.", 0);
          if(end != string::npos) s2->erase(end, 21);
          break;
      }
      case CDP: {
          string::size_type end = s2->find(".1.3.6.1.4.1.9.9.23.1.2.1.1.", 0);
          if(end != string::npos) s2->erase(end, 28);
          break;
      }
      case NEIGHBORDISCOVERY: {
          string::size_type end = s2->find(".1.3.6.1.4.1.9.10.86.1.1.3.1.3.", 0);
          if(end != string::npos) s2->erase(end, 31);
          break;
      }
      case PORTINDEX_TO_PORTNUM: {
          string::size_type end = s2->find(".1.3.6.1.2.1.17.4.3.1.2.", 0);
          if(end != string::npos) s2->erase(end, 24);
          break;
       }
      case PORTINDEX_TO_MAC: {
          string::size_type end = s2->find(".1.3.6.1.2.1.17.4.3.1.1.", 0);
          if(end != string::npos) s2->erase(end, 24);
          break;
       }
      case SYSTEM_NAME: {
          string::size_type end = s2->find(".1.3.6.1.2.1.1.5.", 0);
          if(end != string::npos) s2->erase(end, 17);
          break;
       }
      case SYS_DESCR: {
          string::size_type end = s2->find(".1.3.6.1.2.1.1.1.0.", 0);
          if(end != string::npos) s2->erase(end, 19);
          break;
      }

      default: { break;}
  }
}
//----------------------------------------------------------
void snmpRec::format_mac(string *s2)
{
  if(s2->length() == 7) {
      for(string::iterator i=s2->begin(); i!=s2->end(); i++) {
         if(i!=s2->end()) {
             char c=*i;
             char c2=*(i+1);
              if( c==c2 && c=='\\') {
                  s2->erase(i, i+1);
                 break;
              }
          }
      }
  }

  if(s2->length() == 6)
  {
      char myC[6][8];
      string myBuf;
      for (int i=0; i<6; i++) {
          if(i!=0) myBuf += ".";
          char c=s2->at(i);
          sprintf(myC[i], "%02x", (unsigned int) c);
          myBuf += string(myC[i]);
      }
      *s2=myBuf;
      return;
  }
  string::size_type end;
  while(1) {
      end = s2->find(" ", 0);
      if(end != string::npos) s2->replace(end, 1, 1, '.');
      else break;
  }
}


//----------------------------------------------------------
void snmpRec::format_arp_index(string *i)
{

  if(i->length()==0) {
      snmpComment("\tformat_arp_index( NULL )");
      return;
  }

  if(DEBUG) cout << "before format_indices() we have: " << *i << "\n";

  format_indices(i, ARP);

  if(DEBUG) cout << "format_indices() created: " << *i << "\n";

  // make index and ip delimeter a space
  string::size_type end = i->find(".", 0);
  if(end != string::npos) i->replace(end, 1, 1, ' ');
  else snmpComment("\tformat_arp_index() : BAD");
}

//----------------------------------------------------------
int snmpRec::get_Value(u_char ** buf, const netsnmp_variable_list * var)
{
    size_t buf_len = 512, out_len = 0;

    switch (var->type) {
    case ASN_INTEGER:
        return sprint_realloc_integer(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_OCTET_STR:
        return sprint_realloc_octet_string(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_BIT_STR:
        return sprint_realloc_bitstring(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_OPAQUE:
        return sprint_realloc_opaque(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_OBJECT_ID:
        return sprint_realloc_object_identifier(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_TIMETICKS:
        return sprint_realloc_timeticks(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_GAUGE:
        return sprint_realloc_gauge(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_COUNTER:
        return sprint_realloc_counter(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_IPADDRESS:
        return sprint_realloc_ipaddress(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
   case ASN_NULL:
        return sprint_realloc_null(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_UINTEGER:
        return sprint_realloc_uinteger(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    case ASN_COUNTER64:
        return sprint_realloc_counter64(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    default:
        DEBUGMSGTL(("sprint_by_type", "bad type: %d\n", var->type));
        return sprint_realloc_badtype(buf, &buf_len, &out_len, 1, var, 0, 0, 0);
    }
}

//----------------------------------------------------------
bool snmpRec::get_record(const oid * objid, size_t objidlen, const netsnmp_variable_list * variable, char *n, char *v)
{
  int             buf_overflow = 0;
  u_char         *buf = NULL;
  size_t          buf_len = 512, out_len = 0;

  if ((buf = (u_char *) calloc(buf_len, 1)) == NULL) return false;

  bzero(buf, buf_len);

  netsnmp_sprint_realloc_objid_tree( &buf, &buf_len, &out_len, 1, &buf_overflow, objid, objidlen);

  if(buf_overflow) { SNMP_FREE(buf); return false; }
  strncpy(n , (char *)buf, 512);

  bzero(buf, buf_len);
  if( !get_Value(&buf, variable)) { SNMP_FREE(buf); return false; }
  //v = new string( (const char *) buf);
  strncpy(v , (char *)buf, 512);

  SNMP_FREE(buf);
  return true;
}

//----------------------------------------------------------
bool snmpRec::update_oid(unsigned int oid_choice, oid *r, size_t *len)
{

    switch(oid_choice)
    {
        case VLANS:  { // any of the switch ifDescr
                //snmpComment("VLANS OID Choice");
                //oid myOID[10] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2};
                oid myOID[12] = {1,3,6,1,2,1,47,1,2,1,1,2};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case IFINDEX_TO_IFNAME:  { // any of the switch ifDescr
                //snmpComment("IFINDEX_TO_IFNAME OID Choice");
                oid myOID[11] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case IFDESCR:  {
                //snmpComment("IFDESCR OID Choice");
                oid myOID[10] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case IFENTRY:  {
                //snmpComment("IFENTRY OID Choice");
                oid myOID[10] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 7};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case PORTNUM_TO_IFINDEX:  { // cisco bridge port to ifIndex
                //snmpComment("PORTNUM_TO_IFINDEX OID Choice");
                oid myOID[11] = {1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case PORTINDEX_TO_PORTNUM:  { //(h2) 3com, foundry, cisco portIndex to Port#
                snmpComment("PORTINDEX_TO_PORTNUM OID Choice");
                oid myOID[11]  ={1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case PORTINDEX_TO_MAC:  { //(h3) 3com, foundry, cisco portIndex to mac
                //snmpComment("PORTINDEX_TO_MAC OID Choice");
                oid myOID[11]={1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 1};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case NEIGHBORDISCOVERY: {
                //.1.3.6.1.4.1.9.10.86.1.1.3.1.3
                snmpComment("NEIGHBORDISCOVERY OID Choice");
                oid myOID[14]={1, 3, 6, 1, 4, 1, 9, 10, 86, 1, 1, 3, 1, 3};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case ARP:  {
                //snmpComment("ARP OID Choice");
                oid myOID[10]={1, 3, 6, 1, 2, 1, 4, 22, 1, 2};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case IF_STATUS:  {
                oid myOID[10]={1, 3, 6, 1, 2, 1, 2, 2, 1, 7};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case CDP:  {
                oid myOID[13]={1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case SYS_DESCR: {
                //snmpComment("SYS_DESCR OID Choice");
                oid myOID[9]={1, 3, 6, 1, 2, 1, 1, 1, 0};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
                break;
        }
        case SYSTEM_NAME: {
                //snmpComment( "SYSTEM_NAME OID Choice");
                oid myOID[8]={1, 3, 6, 1, 2, 1, 1, 5};
                memmove(r, myOID, sizeof(myOID));
                *len = sizeof(myOID) / sizeof(oid);
        }
        default: {
                cout << "UNDEFINED OID Choice\n";
                return false;
        }
    }
    return true;
}




//----------------------------------------------------------
void snmpRec::format_value(string *v)
{
  fmt f;
  string::size_type end = v->find_first_of("\"", 0);
  if( end != string::npos) {
      string::size_type end2  = v->find_last_of("\"", v->length());
      if( end2 != string::npos) {
          v->erase(0, end+1);
          end2  = v->find_last_of("\"", v->length());
          v->erase(end2, v->length());
          return;
      }
  }

  if(v->length()==0) return;

  end = v->find_first_of(":", 0);
  v->erase(0, end+1);
  if(v->length()==0) return;

  if(v->at(0) == '-') v->erase(0, 1);
  if(v->length()==0) return;
  *v = f.trim(*v);

}
//-------------------------------------------------------
void snmpRec::format_if_status(string *v2)
{
  fmt f;
  list_t items = f.split(*v2, ':');
  string myS=items.back();  // "up(1)" or "down(2)"  (my quotes)
  *v2=f.trim(myS);
}

//---------------------------------------------------------
void snmpRec::format_neighbors(string *s1, string *s2)
{
  if(DEBUG) cout << "format_neighbors(" << *s1 << ", "<< *s2 << ")\n";
  // make IPv6 Address (s1)
  fmt f;
  list_t words = f.split(*s1, '.');
  if(!words.size()) return;
  string vlan=words.front();
  s1->clear();
  *s1=string(vlan+"|");

  words.pop_front();
  words.pop_front();
  words.pop_front();

  list_t nibbles;

  unsigned int index=0;
  for(list_t::iterator w=words.begin(); w!=words.end(); w++, index++) {
      *s1+= f.octet_to_hex(*w);
      if(index%2 && index < 15) *s1+=":";
  }
  if(DEBUG) cout << "format_neighbors():  s1 is now:  " << *s1 << "\n";

  // mac address (s2)
  list_t mac_words = f.split(*s2, ' ');
  if(!mac_words.size()) return;
  mac_words.pop_back();
  mac_words.pop_back();
  *s2 = f.flatten(mac_words, '.');
}


//-------------------------------------------------------
void snmpRec::format_cdp_string(string index, string *v2)
{
  fmt f;

  list_t index_items = f.split(index);
  string s1 = index_items.front();

  index_items  = f.split(*v2, ':');  // data to right of colon
  string myS=index_items.back();
  myS = f.remove_quot(myS);

  if(s1=="4")
  {
      list_t my_list = f.split(myS, ' ');
      int myIP[4];
      uint num=0;

      for(list_t::iterator i=my_list.begin(); i!=my_list.end() && num<4; i++) {
          string myS(*i);
          myIP[num++] = (int)strtol( (char *)myS.c_str(), NULL, 16);
      }
      char my_addr[16];
      sprintf(my_addr, "%d.%d.%d.%d", myIP[0], myIP[1], myIP[2], myIP[3]);
      *v2 = string(my_addr);
      return;
  }

  else if(s1=="8")
  {
      char myStype[16];

      int num = return_sysType_id(myS);
      sprintf(myStype, "%d", num);
      if(num==0) cout << "MYS: " << myS << "\t(s1=" << s1 << ")\n";
      *v2 = string(myStype);
      return;
  }

  list_t myString=f.split(myS, ':');
  string endString= f.trim(myString.back());

  if(s1=="6" || s1== "11") {
      *v2 = endString;
  }
  else if(s1=="7") {
      if(format_port(&endString)) *v2=endString;
  }
}

//----------------------------------------------------------
// Called from getWalk() only
//----------------------------------------------------------
bool snmpRec::format_records(unsigned int oid_choice, string *s1, string *s2)
{
  if(s2==0 || s1==0) {
      char myBuf[1024];
      sprintf(myBuf, "format_records(NULL) oid_choice = %d \n-----------------\n", oid_choice);
      snmpComment(myBuf);
      return false;
  }

  //snmpComment("format_records(" + *s1 + ", " + *s2 + ")");

  fmt f;

  *s2 = f.trim(*s2);
  if(s2->length() == 0) {
      snmpComment("s2 is empty now\n");
      return false;
  }
  format_value(s2);

  *s1 = f.trim(*s1);
  if(s1->length() == 0) {
      snmpComment("s1 is empty now\n");
      return false;
  }

  switch(oid_choice)
  {
      case IFINDEX_TO_IFNAME: {
                if(format_port(s2) == false) return false;
                format_indices(s1, IFINDEX_TO_IFNAME);
                break;
      }
      case IFDESCR: {
                if(format_port(s2) == false) return false;
                format_indices(s1, IFDESCR);
                //snmpComment( *s1 + "\t" + *s2 );
                break;
      }
      case VLANS: {
                if(format_port(s2) == false) return false;
                format_indices(s1, VLANS);
                //snmpComment( *s1 + "\t" + *s2 );
                break;
      }
      case PORTINDEX_TO_PORTNUM: {
                snmpComment( "PORTINDEX_TO_PORTNUM: " + *s1 + "\t" + *s2);
                format_indices(s1, PORTINDEX_TO_PORTNUM);
                snmpComment( "END: PORTINDEX_TO_PORTNUM: " + *s1 + "\t" + *s2);
                break;
      }
      case PORTNUM_TO_IFINDEX: {
                format_indices(s1, PORTNUM_TO_IFINDEX);
                //snmpComment( "PORTNUM_TO_IFINDEX: " + *s1 + "\t" + *s2);
                break;
      }
      case PORTINDEX_TO_MAC: {
                format_indices(s1, PORTINDEX_TO_MAC);
                format_mac(s2);
                snmpComment( *s1 + "\t" + *s2);
                break;
      }
      case ARP: {
                //if(DEBUG) cout << "format_records(ARP)\n";
                format_mac(s2);
                format_arp_index(s1);
                break;
      }
      case IF_STATUS: {
                format_indices(s1, IF_STATUS);
                format_if_status(s2);
                break;
      }
      case CDP: {
                format_indices(s1, CDP);
                format_cdp_string(*s1, s2);
                break;
      }
      case NEIGHBORDISCOVERY: {
                if(DEBUG) cout << "format_records(NEIGHBORDISCOVERY):: (" << *s1 << ", " << *s2 << ")\n";
                format_indices(s1, NEIGHBORDISCOVERY);
                format_neighbors(s1, s2);
                if(DEBUG) cout << "AFTER --> format_records(NEIGHBORDISCOVERY):: (" << *s1 << ", " << *s2 << ")\n";
                break;
      }
      default: break;
  }
  //snmpComment("\tEND: format_records(" + *s1 + ", " + *s2 + ")");
  return true;
}


//----------------------------------------------------------
void *snmpRec::get_session(const char *ip,const  char *comm)
{
  struct  snmp_session session;
  char    temp[250];
  void    * sessp;

  // initialize session structure
  if(DEBUG) cout << "Init_SNMP Session\n";
  snmp_sess_init(&session);
  if(DEBUG) cout << "Init_SNMP Session -- don\n";

  // set hostname or IP address (and port)
  snprintf(temp, 250, "%s:%d", ip, 161);
  session.peername = temp;

  session.timeout =   8000000;
  if(DEBUG) cout << "SNMP Timeout set at 800000\n";
  //session.timeout = 800000;
  session.retries = 2;
  if(DEBUG) cout << "SNMP retries=3\n";

  // set the SNMP version number
  session.version = SNMP_VERSION_2c;
  if(DEBUG) cout << "SNMP version2c\n";

  // set the SNMPv1/2c community name used for authentication
  session.community = (unsigned char *)comm;
  session.community_len = strlen(comm);
  if(DEBUG) cout << "comm string " << comm << "\n";

  pthread_mutex_lock(&snmp_mutex);
  while(in_session) pthread_cond_wait(&snmp_cond, &snmp_mutex);
  in_session=true;

  sessp = snmp_sess_open(&session);
  if(DEBUG) cout << "SNMP session is now open\n";


  for (uint i = 1; i < NAC_THREADS; i++) pthread_cond_signal(&snmp_cond);
  in_session=false;
  if(DEBUG) cout << "SNMP session unlocking\n";
  pthread_mutex_unlock(&snmp_mutex);

  if (!sessp) { cerr << "\n\tSNMP Session Error. \n\n"; return NULL; }

  if(DEBUG) cout << "SNMP session returning no error\n";
  return sessp;
}

// initialize session structure
//----------------------------------------------------------
void snmpRec::init_snmp_session()
{
  struct  snmp_session session;
  init_snmp("NACman");
  SOCK_STARTUP;
  snmp_sess_init(&session);
  SNMP_SET_LIBS;
  SNMP_SET_QKPR;
  SNMP_SET_OIDS;
  in_session=false;
  pthread_mutex_init(&snmp_mutex, NULL);
  pthread_cond_init(&snmp_cond, NULL);
}

//-----------------------------------------------------------------------
//appends snmpwalk records to the walkList
//-----------------------------------------------------------------------
int snmpRec::getWalk(unsigned int oid_choice, const char *cString, const char *peername, walkRecord_t *walkList)
{
                 size_t name_length, rootlen;
                    int count, running, status, check, exitval = 0, numprinted=0;
            netsnmp_pdu *pdu, *response;
  netsnmp_variable_list *vars;
                    oid name[MAX_OID_LEN], root[MAX_OID_LEN];
                 void * sessp;

  sessp = get_session(peername, cString);

  if(sessp==NULL) { cerr << "Unable to perform snmp_sess_open()\n"; return 0; }

  if(!update_oid(oid_choice, root, &rootlen)) return 0;

  // get first object to start walk
  memmove(name, root, rootlen * sizeof(oid));
  name_length = rootlen;

  running = 1;
  check = !netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_WALK_DONT_CHECK_LEXICOGRAPHIC);

  while (running)
  {
        // create PDU for GETNEXT request and add object name to request
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, name, name_length);

        // do the request
        status = snmp_sess_synch_response(sessp, pdu, &response);

        if (status == STAT_SUCCESS) {

            if (response->errstat == SNMP_ERR_NOERROR) {

                // check resulting variables
                for (vars = response->variables; vars; vars = vars->next_variable)
                {
                    if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
                    {
                        // not part of this subtree
                        running = 0;
                        continue;
                    }

                    char n[512], v[512];
                    if(get_record (vars->name, vars->name_length, vars, n, v))
                    {
                        string *s1 = new string(n);
                        string *s2 = new string(v);
                        if(format_records(oid_choice, s1, s2)) {
                            walkList->insert( make_pair (*s1, s2));
                            numprinted++;
                        }
                    }
                    else { if(!SILENT) cout << "\tERROR: Unable to get VARS\n"; fflush(stdout); }

                    if ((vars->type != SNMP_ENDOFMIBVIEW) && (vars->type != SNMP_NOSUCHOBJECT) &&
                        (vars->type != SNMP_NOSUCHINSTANCE))
                    { // not an exception value
                        if (check && snmp_oid_compare(name, name_length, vars->name, vars->name_length) >= 0)
                        {
                            fprintf(stderr, "Error: OID not increasing: ");
                            fprint_objid(stderr, name, name_length);
                            fprintf(stderr, " >= ");
                            fprint_objid(stderr, vars->name, vars->name_length);
                            fprintf(stderr, "\n");
                            running = 0;
                            exitval = 1;
                        }
                        memmove((char *) name, (char *) vars->name, vars->name_length * sizeof(oid));
                        name_length = vars->name_length;
                    }
                    else running=0; // an exception value, so stop
                }
           }

           else { // error in response, print it
                running = 0;
                if (response->errstat == SNMP_ERR_NOSUCHNAME) printf("End of MIB\n");
                else {
                    fprintf(stderr, "Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
                    if (response->errindex != 0)
                    {
                        fprintf(stderr, "Failed object: ");
                        for (count = 1, vars = response->variables;
                             vars && count != response->errindex;
                             vars = vars->next_variable, count++);
                            /*EMPTY*/
                        if (vars) fprint_objid(stderr, vars->name, vars->name_length);
                        fprintf(stderr, "\n");
                    }
                    exitval = 2;
                }
            }

        }

        else if (status == STAT_TIMEOUT)
        {
            snmpComment( "Timeout: No Response from " + string(peername) );
            running = 0;
            exitval = 1;
        }

        else
        {                /* status == STAT_ERROR */
            perror("snmpwalk");
            running = 0;
            exitval = 1;
        }

        if (response)
        {
            snmp_free_pdu(response);
        }

    }

    if (numprinted == 0 && status == STAT_SUCCESS) {
        /*
         * no printed successful results, which may mean we were
         * pointed at an only existing instance.  Attempt a GET, just
         * for get measure.
         */
        pdu = snmp_pdu_create(SNMP_MSG_GET);

        snmp_add_null_var(pdu, name, name_length);

        status = snmp_sess_synch_response(sessp, pdu, &response);
        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            for (vars = response->variables; vars; vars = vars->next_variable) {
                char n[512], v[512];
                if(get_record (vars->name, vars->name_length, vars, n, v)) {
                    string *s1 = new string(n);
                    string *s2 = new string(v);
                    walkList->insert( make_pair (*s1, s2));
                    numprinted++;
                }
            }
        }
        if (response) {
            snmp_free_pdu(response);
        }
 }
  snmp_sess_close(sessp);

  if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_WALK_PRINT_STATISTICS)) {
        printf("Variables found: %d\n", numprinted);
  }
  //SOCK_CLEANUP;
  return exitval;
}

//==============================================================================
int snmpRec::get_vlans_from_list(walkRecord_t List1, walkRecord_t *vlans, const int type)
{
  fmt f;
  walkRecord_t::iterator iter;

  for( iter = List1.begin(); iter != List1.end(); ++iter )
  {
      string *v2 = new string( *iter->second );
      string *v1;
      if(type==ARP) v1 = new string( iter->first );
      else  v1 = v2;

      *v2 = f.fmt_upper(*v2);

      string::size_type end = v1->find(".", 0);
      if(end != string::npos) v1->erase(0, end+1);

      end = v2->find("VLAN", 0);

      if( (end != string::npos) && (v2->find("UNROUTED", 0) == string::npos) )
      {
          v2->erase(end, 4);
          if(v2->at(0) == '-') v2->erase(0, 1);
          *v2 = f.trim(*v2);
          snmpComment("inserting " + *v1 + "\t" + *v2);
          vlans->insert( make_pair( *v1, v2) );  // index -> vlanID
      }
  }
  return vlans->size();
}

//------------------------------------------------------------
bool snmpRec::get_L3_VLANS(walkRecord_t *vlans, sys_t *L3sys)
{
  walkRecord_t *a0 = new walkRecord_t();
  if(vlans == 0) vlans = new walkRecord_t();

  getWalk(IFINDEX_TO_IFNAME, L3sys->comm.c_str(), L3sys->ip.c_str(), a0);
  //getWalk(VLANS, L3sys->comm.c_str(), L3sys->ip.c_str(), a0);

  if( ! get_vlans_from_list(*a0, vlans, (const int) ARP) ) {
      cerr << "get_L3_VLANS(" << L3sys->ip << ", " << L3sys->comm << "):: failed to get_vlans_from_list()\n";
      return false;
  }
  delete a0;
  return true;
}



typedef struct {
  string ip_addr;
  string ip_name;
  string sysType;
  string remote_port;
  string port;
  string vlan;
} cdp_neighbor_t;
//-------------------------------------------------------------
bool snmpRec::get_cdp(string L2, string comm)
{
  map<string, cdp_neighbor_t *> CDP_neighbor;
  walkRecord_t *a0 = new walkRecord_t();
  walkRecord_t *a1 = new walkRecord_t();
//marker

  getWalk(CDP, comm.c_str(), L2.c_str(), a0);
  if(a0==0) {
     cout << "Failed to get CDP data from getWalk()\n";
     return false;
  }
  getWalk(IFINDEX_TO_IFNAME, comm.c_str(), L2.c_str(), a1);
  if(a1==0) {
     cout << "Failed to get IFINDEX_TO_IFNAME data from getWalk()\n";
     return false;
  }

  walkRecord_t::iterator iter, fnd;

  for( iter = a0->begin(); iter != a0->end(); ++iter )
  {
     string idx = iter->first;
     string::size_type loc = idx.find(".", 0);
     string field_id = idx.substr(0, loc);
     idx.erase(0,loc+1);

     loc = idx.find(".", 0);
     string ifindex = idx;
     ifindex.erase(loc);

     string val = *iter->second;
     cdp_neighbor_t *cN = 0;

     if( CDP_neighbor.find(idx) != CDP_neighbor.end() ) {
         cN = CDP_neighbor[idx];
     } else {
        cN = new cdp_neighbor_t();
        CDP_neighbor[idx]=cN;
     }
     if(field_id=="4") {
         cN->ip_addr=val;
         fnd= a1->find(ifindex);
         if(fnd != a1->end()) {
             cN->port = *fnd->second;
         }
     }
     else if(field_id=="8") cN->sysType=val;
     else if(field_id=="6") cN->ip_name=val;
     else if(field_id=="7") cN->remote_port=val;
     else if(field_id=="11") cN->vlan=val;
  }

  uint num=1;
  for(map<string, cdp_neighbor_t *>::iterator i=CDP_neighbor.begin(); i!= CDP_neighbor.end(); i++)
  {
      cdp_neighbor_t *cN = i->second;
      cout << "---------------------------------------------------\n";
      cout << num++ << ".\n";
      cout << "\tRemote Switch:\t" << cN->ip_name << endl;
      cout << "\t\t\t" << cN->ip_addr << endl;
      cout << "\tRemote Port:\t" << cN->remote_port << endl;
      cout << "\tVlan Number:\t" << cN->vlan << endl;
      cout << "\tSystem Type:\t" << cN->sysType << " ";
      int num = atoi(cN->sysType.c_str());
      switch (num) {
                case _3COM_:
                    cout << "(3Com)";
                    break;
                case _FOUNDRY_:
                    cout << "(Foundry)";
                    break;
                case _AP_:
                    cout << "(Access Point)";
                    break;
                case _CISCO_:
                    cout << "(Cisco Switch)";
                    break;
                case _C2948_:
                    cout << "(C2948)";
                    break;
                case _C2950_:
                    cout << "(C2950)";
                    break;
                case _C2960_:
                    cout << "(C2960)";
                    break;
                case _C2970_:
                    cout << "(C2970)";
                    break;
                case _C3750_:
                    cout << "(C3750)";
                    break;
                case _CAT4000_:
                    cout << "(CAT4000)";
                    break;
                case _C2980_:
                    cout << "(C2980)";
                    break;
                case _C6509_:
                    cout << "(C6509)";
                    break;
                case _FW_:
                    cout << "(CASA5520 FW)";
                    break;
                case _NEXUS_VDC_:
                    cout << "(_NEXUS_VDC_)";
                    break;
                case _NEXUS_NO_SSH_:
                    cout << "(_NEXUS_NO_SSH_)";
                    break;
                default:
                        cout << "(Undefined switch type)";
      }
      cout << "\n\tLocal Port:\t" << cN->port << endl;
      cout << "\n---------------------------------------------------\n\n";
  }
  cout << (num-1) << " CDP Neightbors detected for switch IP " << L2 << "\n\n";
  return true;
}
//-----------------------------------------------------------------------------
void process_arp(walkRecord_t *walkRecord, sys_t *L3sys, walkRecord_t *vlans, unsigned int isIPv6)
{
  fmt f;

  if(DEBUG) { cout << "process_arp(isIPv6=" << isIPv6 << ")\n"; }

  for( walkRecord_t::iterator iter=walkRecord->begin(); iter != walkRecord->end(); iter++)
  {
      string *v1 = new string( iter->first );
      if(DEBUG) { cout  << "process_arp():  Processing " << *v1 << "\n"; }

      string::size_type end;

      if(!isIPv6) {
          end = v1->find(" ", 0);
          if(end == string::npos)  {
             if(DEBUG) cout << "Failed to find non-ipv6 vlan in the string " << *v1 << "\n";
             continue;
          }
      }
      else {
          end = v1->find("|", 0);
          if(end == string::npos) {
              if(DEBUG) cout << "Failed to find vlan in the string " << *v1 << "\n";
              continue;
          }
      }

      string vlan;
      string ip_addr;
      string::size_type v1Size = v1->size();
      ip_addr = v1->substr(end+1, v1Size);
      ip_addr = f.fmt_ip(ip_addr);
      v1->erase(end, v1Size);
      vlan=*v1;

      walkRecord_t::iterator vFind = vlans->find( vlan );
      if(vFind == vlans->end() ) continue;

      string fVlan=*vFind->second;
      if(DEBUG) { cout << " found vlan=" << vlan << "\n"; fflush(stdout);}

      aList_t::iterator aIter = L3sys->A.find(  *iter->second );  // looking for mac address in ARP

     // if "IP addresses are in different networks for this mac address" then it's not clear how to handle.
     // it should flag a conflict, but it's perfectly legitimate as long as it's in the same enclave.
     // To accommodate in polling would require a complete redefinition of the polling table's primary key.
     // It would change to pk = [mac, l2_id]
     //
      if( aIter == L3sys->A.end() || vlan!=fVlan) // not in ARP, or the vlans are different
      {
          arp_record_t *aRec = new arp_record_t();
          aRec->mac = *iter->second;
          aRec->L2_found = false;
          aRec->ip = ip_addr;
          aRec->vlan = *vFind->second;
          int myVlan = atoi ( (char *)aRec->vlan.c_str());
          aRec->ips.insert( make_pair( aRec->ip, myVlan));
          L3sys->A.insert( make_pair( aRec->mac, aRec) );
      }
      else {
          // ????  problem here.
          // but what if the host is on more than one network?
          // better to make [ip,vlan] a tuple to be added to polling information.
          arp_record_t *aRec = aIter->second;
          int myVlan = atoi ( (char *)aRec->vlan.c_str());
          aRec->ips.insert( make_pair(ip_addr, myVlan));
      }
  }
}
//int get_arp_data(string ip, string comm, aList_t *A)
//-------------------------------------------
void snmpRec::get_arp(sys_t *L3sys)
{
  fmt f;
  walkRecord_t *a1, *vlans, *tmpVlans;
  walkRecord_t::iterator iter;

  vlans=new walkRecord_t();
  tmpVlans=new walkRecord_t();

  //flawed in that we are picking up potentially much more information that we need.
  // best to match that which is available in the database to that which is in router first.
  // if there's more defined in the router, ignore it.

  // added code in polling.cpp:get_L3_Routers() to populate L3sys->vlans
  if(L3sys->vlans.size()==0) snmpComment("ERROR::: DB Defined VLANS for L3 " + L3sys->L3+ " is empty");
  else if(DEBUG) {
      for(map_t::iterator i = L3sys->vlans.begin(); i!= L3sys->vlans.end(); i++)
         cout << "Defined: Vlan " << i->first << "\n";
  }

  if( !get_L3_VLANS(tmpVlans, L3sys) ) {
      if(!SILENT) cout << "get_arp():: failed to get_L3_VLANS(" << L3sys->L3 << ")\n";
      return;
  }

  for(iter=tmpVlans->begin(); iter!= tmpVlans->end(); iter++) {
      //if the router vlan is not in the database, remove it from the vlans list
      string vlan = *(iter->second);
      snmpComment("Searching for vlan " + vlan);

      if(L3sys->vlans.find(vlan) != L3sys->vlans.end()) {
          snmpComment("keeping VLAN " + vlan);
          if(DEBUG) cout << "SNMP Retrieved vlan record: " << iter->first << ", " << *iter->second << " (" << L3sys->ip << ")\n";
          vlans->insert (make_pair (iter->first, iter->second));
      }
  }

  if(vlans->size()==0) {
      cout << "PROBLEM::  " << L3sys->L3 << " has no vlans.... \n\n";
      send_error( "PROBLEM::  " + L3sys->L3 + " has no vlans.... \n\n");
      return;
  }

  a1 = new walkRecord_t();
  if(DEBUG) {
      cout << "  getWalk(ARP, " << L3sys->comm << ", " << L3sys->ip << ", a1)\n";
      fflush(stdout);
  }
  getWalk(ARP, L3sys->comm.c_str(), L3sys->ip.c_str(), a1);
  if(DEBUG) {
      cout << "\t# getWalk(ARP, " << L3sys->comm << ") returned with " << a1->size() << " records\n";
      fflush(stdout);
  }

  process_arp(a1, L3sys, vlans, 0);

  if(L3sys->ipv6_ready != "Y")  return;

  walkRecord_t *aN = new walkRecord_t();
  string ip_addr = f.fmt_ip_for_network(L3sys->ip);
  if(DEBUG) { cout << "attempting IPv6 Neighbor on " << ip_addr << "\n"; fflush(stdout); }
  getWalk(NEIGHBORDISCOVERY, L3sys->comm.c_str(), ip_addr.c_str(), aN);
  if(aN->size()) {
      if(DEBUG) { cout << aN->size() << " total DISCOVERY records retrieved for " << ip_addr << "\n"; fflush(stdout); }
      process_arp(aN, L3sys, vlans, 1);
  }
  else if(DEBUG) { cout << "No DISCOVERY records retrieved for " << ip_addr << "\n"; fflush(stdout); }
}


//-------------------------------------------
void snmpRec::get_3com_bridge(string ip, string L3, string comm, vector<polling_record *> *P, map_t ports)
{
  walkRecord_t *h2, *h3;
  walkRecord_t::iterator h2i, h3Find;

  h2=new walkRecord_t();
  h3=new walkRecord_t();

  getWalk(PORTINDEX_TO_PORTNUM, comm.c_str(), ip.c_str(), h2);

  if(h2->size() ==0) {
      snmpComment("\n\t3com:: h2 is empty");
      return;
  }

  getWalk(PORTINDEX_TO_MAC, comm.c_str(), ip.c_str(), h3);
  if(h3->size()==0) {
      snmpComment("\n\t3com: h3 is empty");
      return;
  }

  // get polling List, P
  for( h2i = h2->begin(); h2i != h2->end(); h2i++ )  // h2: portIndex -> portNumber (ifName)
  {
      //h2(2) == port#
      //h2(1) == pID
      //h3(1) == pID
      //h3(2) == mac
      //--------------
      //h2(1) == h3(1)

      snmpComment(" h2: portIndex -> portNumber: " + h2i->first + " " + *h2i->second);

      if( ports[ *h2i->second ] != 1 )
      {
          h3Find = h3->find( h2i->first );

          if( h3Find != h3->end() ) // h3Find holds the mac
          {
              polling_record *pr;
              pr = new polling_record();
              pr->portNum = *h2i->second;
              pr->ifName = *h2i->second;

              snmpComment("IFNAME: " + pr->ifName);

              pr->L3 = L3;
              pr->L2 = ip;
              pr->vlan = "local";
              pr->mac = *h3Find->second;
              pr->dt2= current_timestamp;
              if( P->capacity() >= (P->size()-1) ) P->reserve(P->size() + 20);
              P->push_back(  pr );
          } else {
              snmpComment("Unable to find the h3 for : " +  h2i->first );
          }
      }
  }
}

//-------------------------------------------
// get IFIndex -> ifName (or ifDescr)
//-------------------------------------------
uint snmpRec::get_IF_indexes(sys_t *rec, walkRecord_t *h0)
{
  if(rec->sysType == _3COM_ || rec->sysType == _FOUNDRY_) {
      getWalk(IFDESCR, rec->comm.c_str(), rec->ip.c_str(), h0);
  }
  else if(rec->sysType == _NEXUS_  || rec->sysType == _NEXUS_VDC_ || rec->sysType == _NEXUS_NO_SSH_ ) {
      getWalk(IFDESCR, rec->comm.c_str(), rec->ip.c_str(), h0);
  }
  else {
      getWalk(IFINDEX_TO_IFNAME, rec->comm.c_str(), rec->ip.c_str(), h0);
      if(!h0->size()) {
          cerr << "Failed to get Indexes: get_IF_indexes(" << rec->ip << ", " << rec->comm << ")\n";
      }
  }
  if(h0->size() == 0) {
      //cout << "IFINDEX_TO_IFNAME:" << rec->comm << "\t:" << rec->ip << "\n";
      if(DEBUG) fprintf(stdout, "\tget_IF_indexes(%s, %s) - ERROR: IFINDEX_TO_IFNAME\n", rec->ip.c_str(), rec->comm.c_str());
      return 0;
  }
  return h0->size();
}
//--------------------------------------------------------------------
// get bridge data -- for any type of L2 switch
//--------------------------------------------------------------------
void *snmpRec::get_vlan_polling_data(void *v)
{
  fmt f;
  vlan_P_rec *vP = (vlan_P_rec *) v;
  walkRecord_t *h0 = vP->h0;
  sys_t *rec= vP->rec;
  walkRecord_t *portMapping = vP->portMapping;
  walkRecord_t *h1, *h2, *h3;
  walkRecord_t::iterator h1i, h2i, h0Find, pFind, h3Find;
  string v_comm;

  if(vP->vlan.length() == 0) {
     if(DEBUG) cout << "get_vlan_polling_data(vlan.length==0) :: returning 0\n";
      return 0;
  }
  if(rec->sysType == _NEXUS_VDC_ ) {
     if(DEBUG)  cout << "get_vlan_polling_data(_NEXUS_VDC_) :: returning 0\n";
     return 0;
  }
  else if(rec->sysType == _NEXUS_NO_SSH_ ) {
     if(DEBUG)  cout << "get_vlan_polling_data(_NEXUS_NO_SSH_) :: returning 0\n";
     return 0;
  }

  if(DEBUG) cout << "get_vlan_polling_data(vlan=" << vP->vlan << ")\n";

  string vlan = f.fmt_upper( vP->vlan );

  string::size_type loc = vlan.find("VLAN", 0);
  if( loc != string::npos) {
      if(DEBUG) cout << "Found VLAN in the vlan at position " << loc << "  vlan: '" << vlan << "'\n";
      vlan.erase(loc, 4);
      string myS= f.trim(vlan);
      vlan=myS;
  }
  if(DEBUG) cout << "Vlan: " << vlan << "\n";


  if(rec->sysType == _3COM_ or rec->sysType == _FOUNDRY_) { v_comm =  rec->comm; }
  else { v_comm = rec->comm + '@' + vlan; }

  // get PortNumber -> IFIndex
  //--------------------------------------
  h1=new walkRecord_t();
  getWalk(PORTNUM_TO_IFINDEX, v_comm.c_str(), rec->ip.c_str(), h1);

  if(h1->size() <= 1)
  {
      v_comm = rec->comm + "@1";
      snmpComment("FAILED TO GET INDEXES FOR this switch (" + rec->ip + ") on VLAN " + vlan + ": Trying default vlan 1\n");
      getWalk(PORTNUM_TO_IFINDEX, v_comm.c_str(), rec->ip.c_str(), h1);
      if(!h1->size()) {
          snmpComment( "FAILED TO GET INDEXES FOR THIS switch: " + rec->ip + "\n");
          return 0;
      }
      snmpComment("\tSuccessful index retrieval with default vlan 1 for " + rec->ip + "\n");
  }
  if (DEBUG) {
       cout << rec->ip << " H1 size is: " << h1->size() << "\n";
       for(h1i = h1->begin(); h1i != h1->end(); ++h1i )
       { printf("%s\t%s\t%s\n", rec->ip.c_str(), h1i->first.c_str(), (*h1i->second).c_str()); };
  }

  // get PortIndex -> PortNumber
  //--------------------------------------
  h2=new walkRecord_t();
  getWalk( PORTINDEX_TO_PORTNUM, v_comm.c_str(), rec->ip.c_str(), h2);

  if(h2->size() == 0) {
      // try it without the vlan in the comm string
      getWalk( PORTINDEX_TO_PORTNUM, rec->comm.c_str(), rec->ip.c_str(), h2);
      if(h2->size() == 0) {
          snmpComment("ERROR:: (2nd) get_vlan_polling_data(" + rec->ip + " :PORTINDEX_TO_PORTNUM:: (" + v_comm + ")");
          return 0;
      }
  }

  portMapping=new walkRecord_t();
  h3=new walkRecord_t();
  getWalk(PORTINDEX_TO_MAC, v_comm.c_str(), rec->ip.c_str(), h3);
  if(h3->size() == 0) {
      snmpComment("ERROR:: get_vlan_polling_data(" + rec->ip + " :PORTINDEX_TO_MAC:: (" + v_comm + ")");
      getWalk( PORTINDEX_TO_MAC, rec->comm.c_str(), rec->ip.c_str(), h3);
      if(h3->size() == 0) {
          string errorMsg("ERROR:: (2nd) get_vlan_polling_data(" + rec->ip + " :PORTINDEX_TO_MAC:: (" + v_comm + ")");
          send_error(errorMsg);
          if(DEBUG) cout << errorMsg << "\n";
          return 0;
      }
  }

  for( h1i = h1->begin(); h1i != h1->end(); ++h1i )
  {
      h0Find = h0->find( *h1i->second );
      if( h0Find != h0->end() )
      {
          snmpComment("get mapping for H1index " + *h1i->second + " is " + *h0Find->second);

          if(rec->IgnorePorts[*h0Find->second] != 1)
          {
              string s1(h1i->first);
              string *s2 = new string(*h0Find->second);
              portMapping->insert( make_pair( s1, s2)); // port number  and ifName
          }
          else snmpComment("Ignoring " + *h0Find->second + " -- IP " + rec->ip);

      }
      else snmpComment("Unable to get mapping for H1index " + *h1i->second);
  }

  delete h1;
  //-----------------------------------------------------
  for( h2i = h2->begin(); h2i != h2->end(); ++h2i ) // h2i :: portIndex -> portNumber
  {
      if ( (*h2i->second).length()==0 ) {
          snmpComment("h2i->second is empty: " + rec->ip+"/"+vP->vlan);
          continue;
      }

      try {
         snmpComment("Finding port mapping: " + *h2i->second + " for IPnetwork " + rec->ip+"/"+vP->vlan);
      }
      catch (std::exception& e)
      {
          snmpComment("Finding port mapping: for IPnetwork " + rec->ip+"/"+vP->vlan + "==>> exception caught: " + e.what());
          continue;
      }

      pFind = portMapping->find( *h2i->second );

      if(pFind != portMapping->end())
      {
          snmpComment(" portIndex -> portNumber: " + *h2i->second + " is " +  h2i->first + " (" + *pFind->second + ") ");
          string ifName = *pFind->second;
          string port = pFind->first;
          h3Find = h3->find( h2i->first );  // h3: portIndex# -> mac
          if(h3Find != h3->end())
          {
              snmpComment(" portIndex# -> mac: " + h2i->first + " is " +  *h3Find->second);
              polling_record *pr = new polling_record();
              pr->portNum = port;
              pr->ifName = ifName;
              pr->L3 = rec->L3;
              pr->L2 = rec->ip;
              pr->vlan = vP->vlan;
              pr->mac = *h3Find->second;
              pr->dt2= current_timestamp;
              if( rec->P.capacity() >= (rec->P.size()-1) ) rec->P.reserve(rec->P.size() + 20);
              snmpComment(" \tfound " +  pr->mac);
              rec->P.push_back(  pr );
          }
          else snmpComment(" \tportIndex# -> mac: " + h2i->first + " is unknown ???  ");
      }
      else if(DEBUG) snmpComment(" portIndex -> portNumber: " + *h2i->second + " is " +  h2i->first + " (UNDEFINED) ");

  }
  if(DEBUG) {
      for(vector<polling_record *>::iterator p=rec->P.begin(); p!=rec->P.end(); p++) {
          polling_record *myP = *p;
          myP->print_poll_record();
      }
  }
  delete h2;
  delete h3;
  return v;
}
//--------------------------------------------------
int  snmpRec::return_sysType_id(string theS)
{
  fmt f;

  string myS = f.fmt_lower(theS);

  if( myS.find("c3750") != string::npos) return _C3750_;
  if( myS.find("3com") != string::npos) return _3COM_;
  if( myS.find("cat4000") != string::npos) return _CAT4000_;
  if( myS.find("c6509") != string::npos) return _C6509_;
  if( myS.find("s72033") != string::npos) return _C6509_;
  if( myS.find("s6sup2") != string::npos) return _C6509_;
  if( myS.find("c6506") != string::npos) return _C6509_;

  if( myS.find("c2950") != string::npos) return _C2950_;
  if( myS.find("c2960") != string::npos) return _C2960_;
  if( myS.find("c2970") != string::npos) return _C2970_;
  if( myS.find("c2980") != string::npos) return _C2980_;
  if( myS.find("foundry") != string::npos) return _FOUNDRY_;
  if( myS.find("c2948") != string::npos) return _C2948_;
  if( myS.find("n7000") != string::npos) return _NEXUS_;
  if( myS.find("c3500xl") != string::npos) return _NEXUS_;

  if( myS.find("air") != string::npos) return _AP_;
  if( myS.find("cisco ios software, c1") != string::npos) return _AP_;
  if( myS.find("cisco adaptive security appliance") != string::npos) return _FW_;
  if(DEBUG) cout << "UNable to find systeyp for " << myS << endl;

  return 0;

}

//--------------------------------------------------
int snmpRec::get_sysType(string ip, string comm)
{
  walkRecord_t *recs;
  walkRecord_t::iterator iter;

  recs = new walkRecord_t();

  string myS = snmp_get( SYS_DESCR, (char *)comm.c_str(), (char *)ip.c_str());
  int the_return = return_sysType_id(myS);
  return the_return;
}

//-------------------------------------------------------------------------------------
bool snmpRec::get_ifIndex(string ip, string comm, string port, string *if_index)
{
  fmt f;
  walkRecord_t *h0;

  h0=new walkRecord_t();

  int myType = get_sysType(ip, comm);
  if(DEBUG) {
      cout << "get_sysType() returning " << myType << endl;
      fflush(stdout);
  }

  if(myType == _3COM_ || myType == _FOUNDRY_)
  {
      getWalk(IFDESCR, comm.c_str(), ip.c_str(), h0);

      for( walkRecord_t::iterator iter = h0->begin(); iter != h0->end(); ++iter )
      {
          cout << "<!-- " << *iter->second << " -vs- " << port << " -->\n";
          if( f.trim(*iter->second) == port ) {
              *if_index = iter->first;
              return true;
          }
      }
      return false;
  }


  getWalk(IFINDEX_TO_IFNAME, comm.c_str(), ip.c_str(), h0);
  port = f.trim(port);

  if(h0->size() == 0) {
      if(DEBUG) cout << "Unable to get Interfaces (IFINDEX_TO_IFNAME) for " <<  ip << endl;
      return false;
  }
  for( walkRecord_t::iterator iter = h0->begin(); iter != h0->end(); ++iter )
  {
      cout << "<!-- " << *iter->second << " -vs- " << port << " -->\n";
      if( f.trim(*iter->second) == port ) {
          *if_index = iter->first;
          return true;
      }
  }
  return false;
}
// --------------------------------------------------------------------------------
// perform an snmpget on a host using the provided information
// --------------------------------------------------------------------------------
string snmpRec::snmp_get(uint oid_choice, char *cString, char *peername)
{
  struct  snmp_pdu *pdu;
  struct  snmp_pdu *response;

  oid anOID[MAX_OID_LEN];
  size_t  anOID_len = MAX_OID_LEN;

  struct  variable_list *vars;
  int     status;
  string  result;
  void * sessp;

  //init_snmp_session();
  sessp = get_session(peername, cString);
  if(sessp==NULL) { cerr << "Unable to perform snmp_sess_open()\n"; return 0; }

  // Create the PDU for the data for our request.
  pdu = snmp_pdu_create(SNMP_MSG_GET);

  // set up the OID into the root
  update_oid(oid_choice, anOID, &anOID_len);

  snmp_add_null_var(pdu, anOID, anOID_len);
  status = snmp_sess_synch_response(sessp, pdu, &response);

  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
  {
      if (status == STAT_SUCCESS)
      {
          vars = response->variables;
          char n[512], v[512];
          if(get_record (vars->name, vars->name_length, vars, n, v))
          {
              result = v;
          }
      }
      if (response) snmp_free_pdu(response);
  }
  return result;
}

//---------------------------------------------------
// type can be '1' for unblock or '2' for block
//---------------------------------------------------
bool snmpRec::block_port( string ip, string comm, string rw_comm, string port, char type, string *errorBuffer)
{
  string ifNumber;

  if(!get_ifIndex(ip, comm, port, &ifNumber)) {
      *errorBuffer="Unable to get ifIndex\n";
      return false;
  }
  string if_index("1.3.6.1.2.1.2.2.1.7." + ifNumber);

  char *argv[8];
  argv[0]= (char *)malloc(16);
  argv[1]= (char *)malloc(4);
  argv[2]= (char *)malloc(4);
  argv[3]= (char *)malloc( 16 );
  argv[4]= (char *)malloc( 16 );
  argv[5]= (char *)malloc( 32 );
  argv[6]= (char *)malloc( 8 );
  argv[7]= (char *)malloc( 4 );

  strcpy(argv[0], "snmpset");
  strcpy(argv[1], "-v1");
  strcpy(argv[2], "-c");
  strcpy(argv[3], rw_comm.c_str());
  strcpy(argv[4], ip.c_str());
  strcpy(argv[5], if_index.c_str());
  strcpy(argv[6], "integer");
  bzero(argv[7], 4);
  argv[7][0]=type;

  if(snmpset_do(8, argv)) {
      *errorBuffer="Failed to snmpset_do()\n";
      return false;
  }
  else return true;
}



static void optProc(int argc, char *const *argv, int opt)
{
    switch (opt) {
    case 'C':
        while (*optarg) {
            switch (*optarg++) {
            case 'q':
                break;
            default:
                fprintf(stderr, "Unknown flag passed to -C: %c\n",
                        optarg[-1]);
                exit(1);
            }
        }
    }
}

void snmpRecUsage(void)
{
    fprintf(stderr, "USAGE: snmpset ");
    snmp_parse_args_usage(stderr);
    fprintf(stderr, " OID TYPE VALUE [OID TYPE VALUE]...\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr,
            "  -C APPOPTS\t\tSet various application specific behaviours:\n");
    fprintf(stderr, "\t\t\t  q:  don't print results on success\n");
    fprintf(stderr, "\n  TYPE: one of i, u, t, a, o, s, x, d, b, n\n");
    fprintf(stderr,
            "\ti: INTEGER, u: unsigned INTEGER, t: TIMETICKS, a: IPADDRESS\n");
    fprintf(stderr,
            "\to: OBJID, s: STRING, x: HEX STRING, d: DECIMAL STRING, b: BITS\n");
#ifdef OPAQUE_SPECIAL_TYPES
    fprintf(stderr,
            "\tU: unsigned int64, I: signed int64, F: float, D: double\n");
#endif                          // OPAQUE_SPECIAL_TYPES

}

int snmpRec::snmpset_do(int argc, char *argv[])
{
    netsnmp_session session, *ss;
    netsnmp_pdu    *pdu, *response = NULL;
    netsnmp_variable_list *vars;
    int             arg;
    int             count;
    int             current_name = 0;
    int             current_type = 0;
    int             current_value = 0;
    char           *names[SNMP_MAX_CMDLINE_OIDS];
    char            types[SNMP_MAX_CMDLINE_OIDS];
    char           *values[SNMP_MAX_CMDLINE_OIDS];
    oid             name[MAX_OID_LEN];
    size_t          name_length;
    int             status;
    int             exitval = 0;
    int             failures = 0;

    putenv(strdup("POSIXLY_CORRECT=1"));

    // get the common command line arguments
    switch (arg = snmp_parse_args(argc, argv, &session, "C:", optProc)) {
    case -2: exit(0);
    case -1:
        snmpRecUsage();
        exit(1);
    default:
        break;
    }

    if (arg >= argc) {
        fprintf(stderr, "Missing object name\n");
        snmpRecUsage();
        return 3;
    }
    if ((argc - arg) > 3*SNMP_MAX_CMDLINE_OIDS) {
        fprintf(stderr, "Too many assignments specified. ");
        fprintf(stderr, "Only %d allowed in one request.\n", SNMP_MAX_CMDLINE_OIDS);
        snmpRecUsage();
        return 3;
    }

    // get object names, types, and values
    for (; arg < argc; arg++)
    {
        DEBUGMSGTL(("snmp_parse_args", "handling (#%d): %s %s %s\n",
                    arg,argv[arg], arg+1 < argc ? argv[arg+1] : NULL,
                    arg+2 < argc ? argv[arg+2] : NULL));
        names[current_name++] = argv[arg++];
        if (arg < argc) {
            switch (*argv[arg]) {
            case '=':
            case 'i':
            case 'u':
            case 't':
            case 'a':
            case 'o':
            case 's':
            case 'x':
            case 'd':
            case 'b':
#ifdef OPAQUE_SPECIAL_TYPES
            case 'I':
            case 'U':
            case 'F':
            case 'D':
#endif                          // OPAQUE_SPECIAL_TYPES
                types[current_type++] = *argv[arg++];
                break;

            default:
                fprintf(stderr, "%s: Bad object type: %c\n", argv[arg - 1], *argv[arg]);
                break;
            }

        } else {
            fprintf(stderr, "%s: Needs type and value\n", argv[arg - 1]);
            return 3;
        }
        if (arg < argc)
            values[current_value++] = argv[arg];
        else {
            fprintf(stderr, "%s: Needs value\n", argv[arg - 2]);
            return 3;
        }
    }

    SOCK_STARTUP;

    // open an SNMP session
    ss = snmp_open(&session);
    if (ss == NULL) {
        //diagnose snmp_open errors with the input netsnmp_session pointer
        snmp_sess_perror("snmpset", &session);
        SOCK_CLEANUP;
        return 3;
    }

    // create PDU for SET request and add object names and values to request
    pdu = snmp_pdu_create(SNMP_MSG_SET);

    for (count = 0; count < current_name; count++) {
        name_length = MAX_OID_LEN;
        if (snmp_parse_oid(names[count], name, &name_length) == NULL) {
            snmp_perror(names[count]);
            failures++;
        } else
            if (snmp_add_var
                (pdu, name, name_length, types[count], values[count])) {
            snmp_perror(names[count]);
            failures++;
        }
    }

    if (failures) {
        SOCK_CLEANUP;
        return 3;
    }

    // do the request
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {

        if (response->errstat != SNMP_ERR_NOERROR)
        {
            fprintf(stderr, "Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
            if (response->errindex != 0) {
                fprintf(stderr, "Failed object: ");
                for (count = 1, vars = response->variables;
                     vars && (count != response->errindex);
                     vars = vars->next_variable, count++);
                if (vars) fprint_objid(stderr, vars->name, vars->name_length);
                fprintf(stderr, "\n");
            }
            exitval = 2;
        }

    } else if (status == STAT_TIMEOUT) {
        fprintf(stderr, "Timeout: No Response from %s\n", session.peername);
        exitval = 1;
    } else {                    // status == STAT_ERROR
        snmp_sess_perror("snmpset", ss);
        exitval = 1;
    }

    if (response) snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
    return exitval;
}


//----------------------------------------------------------------------------------
bool snmpRec::get_L2_ports_status(string L2_ip_addr, string comm, map_t *L2_ports)
{
  walkRecord_t::iterator iter;
  walkRecord_t *h0  = new walkRecord_t();
  walkRecord_t *h1  = new walkRecord_t();
  map_t myMap;

  int ret = getWalk(IFDESCR, comm.c_str(), L2_ip_addr.c_str(), h1);
  if(h1->size() == 0) {
      fprintf(stderr, "get_L2_ports_status(%s) ::ERROR (%d) [IFDESCR]\n", L2_ip_addr.c_str(), ret);
      L2_ports=0;
      return false;
  }

  ret = getWalk(IFENTRY, comm.c_str(), L2_ip_addr.c_str(), h0);
  if(h0->size() == 0) {
      fprintf(stderr, "get_L2_ports_status(%s) ::ERROR (%d) [IFENTRY]\n", L2_ip_addr.c_str(), ret);
      L2_ports=0;
      return false;
  }

  fmt f;
  walkRecord_t::iterator find_iter;

  for( iter=h0->begin(); iter != h0->end(); iter++)
  {
      find_iter = h1->find( iter->first );
      if(find_iter !=  h1->end())
      {
          string IFname = f.fmt_lower(*(find_iter->second));

          if(IFname.find("vlan", 0) != string::npos) {
              //cout << "Not going to add: " << IFname << "\n";
              continue;
          }

          int status=1;
          string myS(*iter->second);
          if(myS.at(0)=='1') {
              status = 1;
          }
          else if(myS.at(0)=='2') {
              status = 0;
          }
          myMap[*find_iter->second]=status;
      }
  }
  *L2_ports = myMap;
  return true;
}


//------------------------------------------------------------
bool snmpRec::get_VLANS(map_t *vlans, string ip, string comm)
{
  fmt f;

  walkRecord_t *a0 = new walkRecord_t();

  if(vlans == 0) vlans = new map_t();

  getWalk(VLANS, comm.c_str(), ip.c_str(), a0);
  if(a0->size()==0) return false;

  for(walkRecord_t::iterator iter = a0->begin(); iter != a0->end(); ++iter )
  {
      string *v2 = new string( *iter->second );
      *v2 = f.fmt_upper(*v2);

      string::size_type end = v2->find("VLAN", 0);
      if( (end != string::npos) && (v2->find("UNROUTED", 0) == string::npos) )
      {
          v2->erase(end, 4);
          if(v2->at(0) == '-') v2->erase(0, 1);
          *v2 = f.trim(*v2);
          vlans->insert( make_pair( *v2, 1) );
      }
  }
  delete a0;
  return true;
}
