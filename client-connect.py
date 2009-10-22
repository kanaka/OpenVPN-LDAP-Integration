#!/usr/bin/python

usage = """
Usage: common_name=CN ./client-connect.py TMPFILE

OpenVPN client-connect script to assign client IP based on
LDAP/Active group membership. CN is the LDAP Common Name.

Description:
  This script assigns IP addresses to client based on access policies
  from LDAP/Active Directory. Due to a limitation in Windows TUN device
  emulation, each client must be allocated two addresses in the middle
  of a /30 subnet (netmask 255.255.255.252). The first valid pair is
  *.6 and *.5 (because openvpn itself takes the first 4).

  The openvpn server maintains a status file that maps IP addresses
  to active client common name. This is effectively our IP lease file.

  This script requires a configuration file that specifies the LDAP/AD
  connection settings. Here is an example:
      ldap_server = ldap://172.20.0.10
      ldap_user = vpnquery_account
      ldap_password = secret

  The subnet value is determined as follows:
    - Look up the LDAP group memberships for <common_name>
    - If group name is "VPN *" then read 'info' field of that group
    - Search 'info' field for a line in the form vpn* = <access_num>
    - Append <access_num> to the first two octets of the 'server'
      setting for OpenVPN

  Written by Joel Martin <joel_martin@sil.org>
"""

import sys, os, ldap, re
import ConfigParser, StringIO

debug = 0  # 0->none, 1->some, 2->verbose, 3->ldap data
local_config = "client-connect.cfg"

# Regex configuration matching
re_status = re.compile(r"^status (\S+) *(\d+)(?:$|\s)",
                       re.MULTILINE)
re_server = re.compile(r"^server (\d+.\d+).0.0\s255.255.0.0(?:$|\s)",
                       re.MULTILINE)
re_access = re.compile(r"^vpn[^0-9 ]*[\s=:]\s*(\d+)(?:$|\s$)",
                       re.IGNORECASE | re.MULTILINE)

def get_conf(regex, text, file, name):
    re_matches = regex.findall(text)
    if len(re_matches) < 1:
        print "No valid '%s' line found in %s" % (name, file)
        sys.exit(1)
    if len(re_matches) > 1:
        print "Multiple '%s' lines found in %s" % (name, file)
        sys.exit(1)
    return re_matches[0]


# Sectionless config parser
class SimpleConfigParser(ConfigParser.ConfigParser):
    def read(self, filename):
        try:
            text = open(filename).read()
        except IOError:
            pass
        else:
            file = StringIO.StringIO("[default]\n" + text)
            self.readfp(file, filename)

#
class openvpn_allocator:
    def __init__(self):

        # The work dir and configuration file are hard-coded for now.
        # TODO: determine these from the actual parameters/config
        # of the running process
        os.chdir("/etc/openvpn")
        config_file="server.conf"
       
        # OpenVPN calls us with single parameter which is a temp file to
        # write our openvpn client settings into.
        try:
            self.client_file=sys.argv[1]
        except:
            print "client config temp file not specified"
            print usage
            sys.exit(1)
        
        try:
            self.common_name=os.environ['common_name']
        except:
            print "common_name not set"
            print usage
            sys.exit(1)
        try:
            global debug
            debug=int(os.environ['debug'])
        except:
            pass
        
        # Read in our local config settings
        cfg = SimpleConfigParser()
        cfg.read(local_config)
        self.ldap_server = cfg.get("default", "ldap_server")
        self.ldap_user = cfg.get("default", "ldap_user")
        self.ldap_password = cfg.get("default", "ldap_password")
        if debug == 2:
            print "configuration (%s):" % local_config
            print "  ldap_server: %s" % self.ldap_server
            print "  ldap_user: %s" % self.ldap_user
            print "  ldap_password: %s" % self.ldap_password
        
        # Read in the global openvpn configuration
        try:
            config = open(config_file).read()
        except:
            print "Could not read %s" % config_file
            sys.exit(1)
        
        # Extract settings from openvpn configuration
        (self.status_file, secs) = get_conf(re_status, config,
                                            config_file, 'status')
        if secs != "1":
            print "Status file update frequency must be 1 sec"
            sys.exit(1)
        if debug: print "Status file:", self.status_file

        self.full_subnet = get_conf(re_server, config, config_file, 'server')
        if debug: print "Full Class B Subnet:", self.full_subnet

    def read_status(self):
        # Read in the runtime status/lease file
        try:
            self.status = open(self.status_file).readlines()
        except:
            print "Could not read %s" % self.status_file
            sys.exit(1)
        
    # Print an ldap search result
    def print_ldap_lookup(self, results):
        for item in results:
            cn = item[0]
            data = item[1]
            print "\n%s" % cn
            for key in data.keys():
                print "    %s: %s" % (key, data[key])

    def lookup_ldap_subnet(self):
        pw = self.ldap_password

        dn = "cn=%s,cn=Users,dc=dallas,dc=sil,dc=org" % self.ldap_user
        base_dn = "cn=Users,dc=dallas,dc=sil,dc=org"
        filter = "(cn=%s)" % (self.common_name)

        try:
            # TODO: secure connection to the ldap server
            con = ldap.initialize(self.ldap_server)
            con.simple_bind_s(dn, pw)
            res = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter)
        except ldap.LDAPError, e:
            print "Error:", e
            return 0

        if len(res) == 0:
            print "No matches found for %s" % filter
            return 0

        if debug == 3: self.print_ldap_lookup(res)

        if len(res) != 1:
            print "Multiple matches found for %s" % filter
            return 0

        user = res[0][1] # 0->first/only result, 1->data

        # Validate that account is still active (userAccountControl)
        userAccountControl = int(user['userAccountControl'][0])
        if debug: print "userAccountControl: %d" % userAccountControl 
        if userAccountControl & 2:    # Bit 2 means disabled
            print "Account %s is disabled" % self.common_name
            return 0

        # Extract VPN group membership
        memberOf = [x for x in user['memberOf'] if x.startswith('CN=VPN')]
        if debug == 2: print "VPN list:", memberOf
        vpn_cnt = len(memberOf)

        if vpn_cnt == 0:
            print "No VPN group membership"
            return 0
        
        # for each VPN membership, get the access policy from the
        # group info (Notes) field
        access_list = []
        for base_dn in memberOf:
            if debug: print "processing group %s" % base_dn
            try:
                res = con.search_s(base_dn, ldap.SCOPE_SUBTREE)
            except ldap.LDAPError, e:
                print "Error:", e
                return 0
            if debug == 3: self.print_ldap_lookup(res)

            if not res[0][1].has_key('info'):
                if debug: print "No info field in %s" % base_dn
                continue

            info = res[0][1]['info'][0]
            if debug == 2: print "info field:\n%s\n" % info

            # Be flexible about access number in the info field
            re_matches = re_access.findall(info)
            if debug == 2: print "adding access data: %s" % str(re_matches)
            access_list += re_matches

        con.unbind()

        if len(access_list) == 0:
            print "No access controls found in VPN group(s)"
            return 0

        # Prefer the lowest access number (highest priveledge)
        access_list = [int(x) for x in access_list]
        access_list.sort()

        if debug: print "full access_list:", access_list

        # TODO: fix
        self.subnet = "%s.%d" % (self.full_subnet, access_list[0])
        if debug: print "setting subnet to %s" % self.subnet
        return 1

    def allocate_client(self):
        net = self.subnet
        # Extract the IP leases from the status file
        lease={}
        pool=[]
        if debug == 2: print "Status file:"
        self.read_status()
        for line in self.status:
            line = line.strip()
            if line.startswith(net):
                if debug == 2: print "  %s" % line
                (ip, common_name, real_addr, date) = line.split(',')
                lease['ip'] = {'common_name': common_name, 
                                    'real_addr'  : real_addr,
                                    'date'       : date}
                pool.append(int(ip.split('.')[-1]))

        if debug: print "\npool last octet list: %s" % str(pool)

        # Find first available /30 network from the pool
        for quad in range(2,64):
            if pool.count(quad*4-2) == 0:
                new_ip = quad*4-2
                break

        # Assign the address from this subnet pool
        f = open(self.client_file, 'a')
        if debug: print "adding command: ifconfig-push %s.%d %s.%d\n" % \
                        (net, new_ip, net, new_ip-1)
        f.write("ifconfig-push %s.%d %s.%d\n" % 
               (net, new_ip, net, new_ip-1))
        f.close()


if __name__ == "__main__":
    oa = openvpn_allocator()   
    
    if not oa.lookup_ldap_subnet():
        sys.exit(1)

    oa.allocate_client()

    sys.exit(0)
