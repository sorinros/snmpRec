/* fmt.cpp
 * written by Paige Stafford
*/


#include <iostream>
#include <stdio.h>
#include <string>
#include <list>
#include "fmt.hpp"
#include <arpa/inet.h>

using namespace std;

typedef list<string> list_t;

// format string into lower case
string fmt::fmt_lower(string s) const
{
  string s2=s;
  int len=s.length();
  for(int i=0; i<len; i++) { s2[i]=tolower(s[i]); }
  return s2;
}

// format string into upper case
string fmt::fmt_upper(string s) const
{
  string s1= s;
  int len=s.length();
  for(int i=0; i<len; i++) { s1[i]=toupper(s[i]); }
  string *s2 = new string(s1);
  return *s2;
}

string fmt::remove_quot(string s) const
{
  if (s.empty()) return "";
  string myS = s;
  int total_len =  myS.length()-1;
  int len=0;

  while( !myS.empty() && len<total_len) {
      if(myS.at(len) == '\"') myS.erase(len, 1);
      len++;
  }
  return myS;
}

//returns index of the first occurrence ch within the current string,
//starting at index, string::npos if nothing is found.
bool fmt::parse_3(string s, string *s1, string *s2, string *s3)
{
  unsigned int i=0, loc;
  string myS, sList[3];
  myS=s;

  while(i<3) {
      loc=myS.find_first_of(' ');
      if(loc == string::npos) {
          if(i!=2) return false;
          else sList[i++]=myS;
      } else {
          sList[i++]=myS.substr(0, loc);
          myS.erase(0, loc+1);
      }
  }
  *s1 = sList[0];
  *s2  = sList[1];
  *s3  = sList[2];
  return true;
}

//returns index of the first occurrence ch within the current string,
//starting at index, string::npos if nothing is found.
bool fmt::parse_2(string s, string *s1, string *s2)
{
  unsigned int i=0, loc;
  string myS, sList[2];
  myS=s;

  while(i<2) {
      loc=myS.find_first_of(' ');
      if(loc == string::npos) {
          if(i!=1) return false;
          else sList[i++]=myS;
      } else {
          sList[i++]=myS.substr(0, loc);
          myS.erase(0, loc+1);
      }
  }
  *s1 = sList[0];
  *s2  = sList[1];
  return true;
}

// determines the first non-zero bits.
// only valid for subnet masks octets
void fmt::to_binary(int number, int *bits)
{
  if(number <= 1) {
      return;
  }
  int remainder = number%2;
  to_binary(number >> 1, bits);
  *bits += remainder;
}

// only valid for octets -- e.g. decimal value < 256
//--------------------------------------------------
void fmt::binary(int number, string *bits)
{
  if( number < 0 || number > 256) {
      cout << "<p class='subred'>Invalid number for binary():: " << number << "</p>\n"; fflush(stdout);
      return;
  }

  char s[] = "00000000";
  int myInt=number;

  if (myInt >= 128) {
      s[0]='1';
      myInt -= 128;
  }
  if (myInt >= 64) {
      s[1]='1';
      myInt -= 64;
  }
  if (myInt >= 32) {
      s[2]='1';
      myInt -= 32;
  }
  if (myInt >= 16) {
      s[3]='1';
      myInt -= 16;
  }
  if (myInt >= 8) {
      s[4]='1';
      myInt -= 8;
  }
  if (myInt >= 4) {
      s[5]='1';
      myInt -= 4;
  }
  if (myInt >= 2) {
      s[6]='1';
      myInt -= 2;
  }
  if (myInt >= 1) {
      s[7]='1';
      myInt -= 1;
  }
  *bits = s;
}

// remove all new-lines or spaces from front/end of string
string fmt::trim(const string s)
{
  string myS = s;

  if (s.empty()) return myS;

  unsigned int len =  myS.length()-1;

  while( !myS.empty() && isspace((myS.at(len)))) {
      myS.erase(len, 1);
      len--;
  }
  while( !myS.empty() && isspace((myS.at(0)))) {
      myS.erase(0, 1);
  }
  if(myS.length() == 1 && myS.at(0) == ' ') return "";
  return myS;
}


list_t fmt::make_words(string s2) const
{
  return split(s2, '|');
}

// Split string into segments
// segments separated by '.'
list_t fmt::split(string s2) const
{
  list_t *my_list = new list_t();
  *my_list = split(s2, '.');
  return *my_list;
}

// Split string into segments
// segments separated by variable char c
//------------------------------------------
list_t fmt::split(string s2, char c) const
{
  string new_mac;
  string::size_type len, last_pos=0, i;

  list_t *my_list = new list_t();
  list_t::iterator theIterator;

  len=s2.length();

  int size;

  for(i=0; i<len; i++) {
      if(s2[i]==c) {
          size = i-last_pos;
          string new_s = s2.substr(last_pos, size);
          my_list->push_back( new_s );
          if( ( (i+1) < len) && s2[i+1]==c) last_pos=i+1;
          else last_pos=++i;
      }
  }
  /* get the last remaining 'octet'*/
  size = len-last_pos;
  string new_s = s2.substr(last_pos, size);
  my_list->push_back( new_s );
  return *my_list;
}



// format mac address for database storage and comparison
// requires format in (1) xxxx.xxxx.xxxx
// or (2) x.x.x.x.x.x or (3) xx.xx.xx.xx.xx.xx where x is in [0-9, A-z]
// formats (2) and (3) can be mismatched: e.g., x.xx.x.xx.xx.x
// returns empty string if fails to meet these basic formats
string fmt::fmt_mac(string m)
{
  string new_mac;
  list_t my_list;
  list_t::iterator theIterator;

  my_list = split( fmt_upper(trim(m)) );

  string s1 = my_list.front();

  if(s1.size()==4 && my_list.size() != 3) return "";
  else if(my_list.size() != 6 && my_list.size() != 3) return "";

  unsigned int last_pos=0;

  for(theIterator = my_list.begin(); theIterator != my_list.end(); theIterator++)
  {
      string tS = *theIterator;

      if(last_pos++ > 0) new_mac += ".";

      if(tS.length()==4) {
          string tS1 = tS.substr(0, 2);
          string tS2 = tS.substr(2, 2);
          new_mac += (tS1 + "." + tS2);
      }
      else if(tS.length()==2) new_mac += tS;
      else if(tS.length()==1) new_mac += ("0" + tS);
      else if(tS.length()==0) return "";
  }
  return new_mac;
}


// format ip address for database storage and comparison
string fmt::fmt_ip(string ip)
{
  string new_ip;
  list_t my_list;
  list_t::iterator theIterator;

  my_list = split( trim(ip) );

  if(my_list.size()!=4) {
      // if it's an IPv6address
      return fmt_ipv6_address(ip);
  }

  int last_pos=0;
  for(theIterator = my_list.begin(); theIterator != my_list.end(); theIterator++) {
      string tS = *theIterator;
      if(last_pos++ > 0) new_ip += ".";
      if(tS.length()==3) new_ip += tS;
      if(tS.length()==2) new_ip += ("0" + tS);
      if(tS.length()==1) new_ip += ("00" + tS);
  }
  return new_ip;
}

/*----------------------------------------*/
string fmt::fmt_ip_for_network(string ip)
{
  string new_ip;
  list_t my_list;
  list_t::iterator theIterator;

  my_list = split( trim(ip) );

  if(my_list.size()!=4) return "";

  int last_pos=0;
  for(theIterator = my_list.begin(); theIterator != my_list.end(); theIterator++)
  {
     if(last_pos++ > 0) new_ip += ".";

     string myS = *theIterator;
     while( !myS.empty() && myS.at(0)=='0') {
         myS.erase(0, 1);
     }
     if(myS.empty()) myS="0";
     new_ip += myS;
  }
  return new_ip;
}
/*----------------------------------------*/
string fmt::fmt_ip_for_network(string ip)
{
  string new_ip;
  list_t my_list;
  list_t::iterator theIterator;

  my_list = split( trim(ip) );

  if(my_list.size()!=4) return "";

  int last_pos=0;
  for(theIterator = my_list.begin(); theIterator != my_list.end(); theIterator++)
  {
     if(last_pos++ > 0) new_ip += ".";

     string myS = *theIterator;
     while( !myS.empty() && myS.at(0)=='0') {
         myS.erase(0, 1);
     }
     if(myS.empty()) myS="0";
     new_ip += myS;
  }
  return new_ip;
}



//returns the current year as an integer
int fmt::get_current_year()
{
  char *date_time = (char *)malloc(24);
  time_t lt;
  lt=time(NULL);
  strftime(date_time, 24, "%Y",  localtime(&lt));
  date_time[strlen(date_time)]='\0';
  return(atoi(date_time));
}


// Takes three integers to make string with YYYY-MM-DD format
string fmt::fmt_date(int year, int month, int day)
{
  char my_date[32];
  int days_in_month[13] = { 0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

  if(month <= 0 || month > 12) return "";
  if(year < 2000 || year > get_current_year()) return "";

  if(day <= 0 || day > days_in_month[month]) return "";

  bzero(my_date, 32);
  sprintf(my_date, "%d-%02d-%02d", year, month, day);
  string s_date(my_date);
  return s_date;
}

//take string and separated it, at the new-line, into list of strings
list_t fmt::make_lines(string s) const
{
  unsigned int loc;
  list_t v;
  string myS=s;

  while(true) {

      loc=myS.find_first_of('\n');
      if(loc == string::npos) {
          v.push_back(myS);
          break;
      } else {
          v.push_back(myS.substr(0, loc));
          myS.erase(0, loc+1);
      }
  }
  return v;
}


string fmt::make_query_ready(const string s)
{
  string myS = trim(s);
  for (unsigned int pos = 0; pos < myS.length(); pos++ ) {
      if(myS[pos]=='*') myS[pos]='%';
  }
  return myS;
}

string fmt::fmt_badge(const string s)
{
  string myS = trim(s);
  for (unsigned int pos = 0; pos < myS.length(); pos++ ) {
      if(!isdigit(myS[pos])) return "";
  }
  while(myS.length() < 6) {
      myS.insert(0, "0");
  }
  return myS;
}


string fmt::pad(const string s, int len, char c)
{
  string myS = trim(s);
  unsigned int mylen=len;
  while(myS.length() < mylen) myS.insert(0, 1, c);
  return myS;
}

string fmt::to_string(int i)
{
  char myI[64];
  bzero(myI, 64);
  sprintf(myI, "%d", i);
  string myS(myI);
  return myS;
}

string fmt::fmt_to_web(string s)
{
  string myS = trim(s);
  string newS;

  for (unsigned int pos = 0; pos < myS.length(); pos++ )
  {
      if(myS[pos] == '\n') newS += "<br>";
      else newS += myS[pos];
  }
  return newS;
}

// compares two lists of type <string, int>
// returns the elements of map1 that are not in map2
map<string, int> fmt::map_difference(map<string, int> m1,  map<string, int> m2)
{
  map<string, int> myMap;
  map<string, int>::iterator m;

  // initialize both lists values to 1
  for(m = m2.begin();  m != m2.end(); m++) m2[m->first] = 1;

  for(m = m1.begin();  m != m1.end(); m++) {
      // if member of list1 is not in list2, add to myList
      if( m2[m->first] != 1 ) myMap[m->first] = 1;
  }
  return myMap;
}


//----------------------------------------
// 00.00.00.00.00.00 ==>> 0000.0000.0000
//----------------------------------------
string fmt::fmt_mac_for_network(string mac)
{
  list_t my_list = split( trim(mac) );
  if(my_list.size()==3) return mac;
  if(my_list.size()!=6) return "";
  list_t::iterator t = my_list.begin();

  uint c=0;
  string myMac;

  for(list_t::iterator t = my_list.begin(); t != my_list.end(); t++ )
  {
      myMac += *t;
      c++;
      if(c<5 && c%2==0) myMac+= ".";
  }
  return myMac;
}

string fmt::flatten(list_t L, char separator)
{
  string *myS = new string();
  for(list_t::iterator i=L.begin(); i!=L.end(); i++)
  {
      if(i !=L.begin()) *myS += separator;
      *myS += *i;
  }
  return *myS;
}

string fmt::flatten_map(map_t M, char separator)
{
  string *myS = new string();
  for(map_t::iterator i=M.begin(); i!=M.end(); i++)
  {
      if(i !=M.begin()) *myS += separator;
      *myS += i->first;
  }
  return *myS;
}


//inet_pton() and inet_ntop().
//inet_pton() to check the validity of the IPv6 address format which is pretty handy.
//inet_ntop() to get the compressed version of the IP address
//
//Check if IPv6 address is valid
int check_v6_address(string ip_addr)
{
  struct sockaddr_in6 sa6;
  // store this IP address in sa6:
  int status = inet_pton(AF_INET6, (char *)ip_addr.c_str(), &(sa6.sin6_addr));
  if(status!=1) return 0; // ("Invalid IPv6 Address format");
  return 1;
}

string compress_v6(string ip_addr)
{
  // store this IP address in sa6:
  struct sockaddr_in6 sa6;
  int status = inet_pton(AF_INET6, (char *)ip_addr.c_str(), &(sa6.sin6_addr));
  if(status!=1) return string(""); // ("Invalid IPv6 Address format");

  char str[INET6_ADDRSTRLEN];
  // now get it back in compressed format
  inet_ntop(AF_INET6, &(sa6.sin6_addr), str, INET6_ADDRSTRLEN);
  return string(str);
}

string fmt::to_bin(int input_num)
{
  if(input_num >= 255) return "";
  if(!input_num) return "00000000";

  char myNum[8];  bzero(myNum, 8);
  char n[16]; bzero(n, 16);
  strcpy(n, "00000000");

  int num=input_num;

  if (num >= 128) {
      n[0]='1';
      num -= 128;
  }
  if (num >= 64) {
      n[1]='1';
      num -= 64;
  }
  if (num >= 32) {
      n[2]='1';
      num -= 32;
  }
  if (num >= 16) {
      n[3]='1';
      num -= 16;
  }
  if (num >= 8) {
      n[4]='1';
      num -= 8;
  }
  if (num >= 4) {
      n[5]='1';
      num -= 4;
  }
  if (num >= 2) {
      n[6]='1';
      num -= 2;
  }
  if (num >= 1) {
      n[7]='1';
      num -= 1;
  }

  return string(n);
}



//------------------------------------------------------------
unsigned int fmt::add_v6_zeros(string *subnet)
{
  if(!subnet->length()) {
      cout << "<p>add_v6_zeros(NULL)</p>\n";
      return 0;
  }

  list_t my_list=split(*subnet, ':');
  int list_size=my_list.size();

  if(!list_size){
      cout << "<p>add_v6_zeros() -- Empty List</p>\n";
      return 0;
  }

  if(list_size>8) {
      cout << "<p>add_v6_zeros(too large)</p>\n";
      return 0;
  }
  if(list_size==8) {

      if(subnet->find("::", 0) == string::npos) return 1;

      cout << "<p>add_v6_zeros() -- '::' defined when currect count of 16-bit grouping<br>\n<b>";
      cout << *subnet << "</b></p>\n";
      return 0;
  }
  if(list_size < 8)
  {
      if(subnet->find("::", 0) == string::npos) {
          //cout << "<p>add_v6_zeros -- No '::' defined when low count of 16-bit grouping (";
          //cout << my_list.size() << " ea)</p>\n";
          return 0;
      }

      int diff = 8-list_size;

      list_t partsList;

      list_t::iterator id = my_list.begin();
      for(;id!=my_list.end(); id++)
      {
          string subPart=*id;
          if((subPart).at(0)==':') {
              for( int i = 0; i < diff; i++ ) partsList.push_back( "0" );
              subPart.erase(0, 1);
          }
          partsList.push_back(subPart);
      }
      my_list.clear();
      string mySubnet=flatten(partsList, ':');
      my_list=split(mySubnet, ':');
      if(my_list.size() != 8) {
          cout << "<p>add_v6_zeros:: BAD my_list.size(" << my_list.size() << ")</p>\n";
          return 0;
      }
      *subnet=mySubnet;
  }
  return 1;
}


//---------------------------------------------------------
unsigned int fmt::expand_ipv6_address(string *subnet)
{

  list_t my_list= split(*subnet, ':');
  int list_size=my_list.size();

  if(list_size < 8)
  {
      if(!add_v6_zeros(subnet)) return 0;
      my_list.clear();
      my_list=split(*subnet, ':');
  }

  list_t my_new_list;

  for(list_t::iterator i=my_list.begin(); i!=my_list.end(); i++)
  {
      string myNum=*i;
      if(myNum.at(0)==':') {
          myNum.erase(0, 1);
          int padded_0s= 8-my_list.size();
          for(int id=0; id<padded_0s; id++) {
              my_new_list.push_back("0000");
          }
          string myString = pad(myNum, 4, '0');
          my_new_list.push_back( myString );
      }
      else if(!myNum.length() || myNum=="")
      {
          int padded_0s= 8-my_list.size();
          for(int id=0; id<=padded_0s; id++) {
              my_new_list.push_back("0000");
          }
      }
      if(myNum.find(".") != string::npos) {
         string myString = octet_to_hex(myNum);
         my_new_list.push_back( myString );
      }
      else {
          string myString = pad(myNum, 4, '0');
          my_new_list.push_back( myString );
      }
  }
  *subnet=flatten(my_new_list, ':');
  return 1;
}

string fmt::bin_to_hex(string word)
{
  char myWord[16]; bzero(myWord, 16);

  strcpy(myWord, (char *)word.c_str());
  unsigned int num = strtol ((char *)myWord,(char **)&myWord,2); //bin_to_dec(myWord);

  bzero(myWord, 16);
  sprintf(myWord, "%02x", num);
  return string(myWord);
}


string fmt::octet_to_hex(string str)
{
  string myS=trim(str);
  int decNum= atoi( (char *)myS.c_str());
  string theDec=to_bin(decNum);
  // now make it hex
  string myNewNum=bin_to_hex(theDec);
  return myNewNum;
}


unsigned int fmt::fmt_4to6_part(string *subnet)
{
  string mySubnet(*subnet);

  list_t my_list=split(mySubnet, ':');

  if(my_list.size() > 6)   {
      //cout << "<p>Invalid IPV6 address format</p>\n";
      return 0;
  }
  list_t v4_list=split(mySubnet, '.');
  if(v4_list.size() != 4) {
      //cout << "<p>Invalid IPV6 address format</p>\n";
      return 0;
  }
  list_t::iterator i=v4_list.begin();
  // reformat the first string a:1.2.3.4 (remove the "a:")
  string octet1=*i; i++;  // lookslike a:1 "
  string::size_type loc = octet1.rfind(":");
  octet1.erase(0, loc+1);
  string octet2=*i; i++;
  string octet3=*i; i++;
  string octet4=*i;

  string myBack = my_list.back();
  my_list.pop_back();
  if(myBack.at(0)==':') my_list.push_back("");

  string myS=octet_to_hex(octet1);
  myS+=octet_to_hex(octet2);
  my_list.push_back(myS);
  myS.erase();
  myS=octet_to_hex(octet3);
  myS+=octet_to_hex(octet4);
  my_list.push_back(myS);
  *subnet=flatten(my_list, ':');
  cout <<"<p class='s2'>Subnet Now: " << *subnet <<"</p>\n";

  return 1;
}


//--------------------------------------------------------------------------
//format ipv6 addresses to expand with leading zeros
//e.g. 2620:0:2b30:3::23 -->  2620:0000:2B30:0003:0000:0000:0000:0023
// notice -- all caps
//--------------------------------------------------------------------------
string fmt::fmt_ipv6_address(string ip)
{
  if(!ip.length()) return "";

  string subnet = fmt_upper(trim(ip));
  if(!subnet.length()) {
      cout << "<p>fmt_ipv6_addr(empty)</p>\n";
      return "";
  }

  // need to make sure that the last char is not a ':'
  string::size_type loc = subnet.length();
  if(subnet.at(loc-1)==':') subnet += "0";
  if(subnet.at(0)==':') subnet = "0"+subnet;

  list_t my_list = split( subnet ,':');

  int list_size=my_list.size();
  if(!list_size || list_size>8) {
      cout << "<p>fmt_ipv6_addr():: BAD my_list.size(" << list_size << ")</p>\n";
      return "";
  }

  if(list_size < 8)
  {
      string::size_type loc = subnet.find(".");
      if(loc != string::npos && list_size < 6)
      {
          if(!fmt_4to6_part(&subnet)) return "";
          my_list.clear();
          my_list = split( subnet ,':');
          list_size=my_list.size();
      }
  }

  if(!expand_ipv6_address(&subnet)) return "";
  else return (subnet);
}
