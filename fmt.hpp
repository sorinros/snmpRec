/* fmt.hpp */

#ifndef FMT_H
#define FMT_H

#include <iostream>
#include <stdio.h>
#include <string>
#include <list>
#include <map>
#include <stdlib.h>
#include <string.h>



using namespace std;

typedef list<string> list_t;
typedef map<string, int> map_t;

class fmt {
  public:
  list_t make_words(string s2) const;
  list_t split(string) const;
  list_t split(string, char) const;
  string remove_quot(string) const;
  string fmt_mac(string);
  string fmt_ip(string);
  string fmt_ip_for_network(string);
  string fmt_yyyy_mm_dd(string) const;
  string fmt_lower(string) const;
  string fmt_upper(string) const;
  int get_current_year();
  string fmt_date(int, int, int);
  bool parse_3(string, string*, string*, string*);
  bool parse_2(string, string*, string*);
  list_t make_lines(string s) const;
  string trim(const string s);
  string make_query_ready(const string s);
  string fmt_badge(const string s);
  string pad(const string s, int len, const char c);
  void to_binary(int, int*);
  void binary(int, string *);
  string to_string(int i);
  string fmt_to_web(string s);
  map<string, int> map_difference(map<string, int> m1,  map<string, int> m2);
  string remove_html(string);
  string fmt_mac_for_network(string mac);
  string flatten(list_t L, char separator);
  string flatten_map(map_t M, char separator);
unsigned int add_v6_zeros(std::string*);
unsigned int expand_ipv6_address(string*);
string octet_to_hex(string);
unsigned int fmt_4to6_part(string*);
string fmt_ipv6_address(string);
string to_bin(int input_num);
string bin_to_hex(string word);

};

#endif // FMT_H
