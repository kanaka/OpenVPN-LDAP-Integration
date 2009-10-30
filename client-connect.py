#!/usr/bin/python
# Copyright 2009 Summer Institue of Linguistics
# Copyright 2009 Joel Martin <joel_martin@sil.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

usage = """%s

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
      # Query account and password
      ldap_dn = cn=vpnquery_account,cn=users,dc=example,dc=com
      ldap_password = secret
      # Search for "VPN*" groups in ldap_group_dn
      ldap_group_dn = cn=users,dc=example,dc=com

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
            raise
        else:
            file = StringIO.StringIO("[default]\n" + text)
            self.readfp(file, filename)

#
class openvpn_allocator:
    def __init__(self):

        # OpenVPN calls us with single parameter which is a temp file to
        # write our openvpn client settings into.
        try:
            self.client_file=sys.argv[1]
        except:
            print usage % "client config temp file not specified"
            sys.exit(1)
        try:
            self.common_name=os.environ['common_name']
        except:
            print usage % "common_name not set"
            sys.exit(1)
        try:
            self.trusted_ip=os.environ['trusted_ip']
        except:
            print usage % "trusted_ip not set"
            sys.exit(1)
        try:
            global debug
            debug=int(os.environ['debug'])
        except:
            pass
        try:
            global workdir
            workdir=os.environ['workdir']
        except:
            workdir="/etc/openvpn"
        
        # The work dir and configuration file are hard-coded for now.
        # TODO: determine these from the actual parameters/config
        # of the running process
        os.chdir(workdir)
        config_file="server.conf"
       
        # Read in our local config settings
        cfg = SimpleConfigParser()
        cfg.read(local_config)
        self.ldap_server = cfg.get("default", "ldap_server")
        self.ldap_dn = cfg.get("default", "ldap_dn")
        self.ldap_password = cfg.get("default", "ldap_password")
        self.ldap_group_dn = cfg.get("default", "ldap_group_dn")
        if debug >= 2:
            print "configuration (%s):" % local_config
            print "  ldap_server: %s" % self.ldap_server
            print "  ldap_dn: %s" % self.ldap_dn
            print "  ldap_password: %s" % self.ldap_password
            print "  ldap_group_dn: %s" % self.ldap_group_dn
        
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

        # Get the VPN groups
        base_dn = self.ldap_group_dn
        filter = "(cn=VPN*)"
        try:
            # TODO: secure connection to the ldap server
            con = ldap.initialize(self.ldap_server)
            con.simple_bind_s(self.ldap_dn, self.ldap_password)
            res = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter)
        except ldap.LDAPError, e:
            print "Error:", e
            return 0

        if debug >= 3: self.print_ldap_lookup(res)

        # Filter VPN groups that user is member of and
        # that have access control in the info field
        groups = []
        access_list = []
        user_dn = ""
        cname = self.common_name.lower()
        for group in [x[1] for x in res]:
            if not group.has_key('member'): continue
            if not group.has_key('info'): continue
            gname = group['cn'][0]
            if debug >= 3:
                print "searching for '%s' in '%s'" % (cname, gname)
            for user in [x.lower() for x in group['member']]:
                found = False
                # Check if account name and CN are same
                if user.find("=%s," % cname) >= 0: found = True

                # Otherwise do the slower lookups
                if not found:
                    # Get the user's canonical name
                    base_dn = user
                    filter = "(sAMAccountName=%s)" % cname
                    try:
                        res = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter)
                    except ldap.LDAPError, e:
                        print "Error:", e
                        return 0

                    if res: found = True

                if not found: continue

                if debug >= 2:
                    print "found '%s' in '%s'" % (cname, gname)

                info = group['info'][0]
                if debug >= 2:
                    print "info field:\n  %s" % info.replace("\n", "\n  ")

                # Be flexible about access number in the info field
                re_matches = re_access.findall(info)
                if len(re_matches) == 0: continue

                if debug >= 2:
                    print "adding access data: %s\n" % str(re_matches)
                access_list.extend(re_matches)

                user_dn = user
                groups.append(group)
                break

        if len(groups) == 0:
            print "No VPN group membership found for '%s'" % cname
            return 0

        # Read the user's data
        base_dn = user_dn
        filter = "(sAMAccountName=%s)" % cname
        try:
            res = con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter)
        except ldap.LDAPError, e:
            print "Error:", e
            return 0

        con.unbind()

        if debug >= 3: self.print_ldap_lookup(res)
        
        # These conditions really should not happen if we just found
        # the user in a group above.
        if len(res) == 0:
            print "Found '%s' in a group, but LDAP lookup failed" % cname
            return 0
        if len(res) > 1:
            print "Multiple LDAP results for '%s'" % cname
            return 0

        user = res[0][1] # 0->first/only result, 1->data

        # Validate that account is still active (userAccountControl)
        userAccountControl = int(user['userAccountControl'][0])
        if debug >= 2: print "userAccountControl: %d" % userAccountControl 
        if userAccountControl & 2:    # Bit 2 means disabled
            print "Account %s is disabled" % self.common_name
            return 0

        if len(access_list) == 0:
            print "No access controls found in VPN group(s)"
            return 0

        # Prefer the lowest access number (highest priveledge)
        access_list = [int(x) for x in access_list]
        access_list.sort()

        if debug: print "Full access_list:", access_list

        self.subnet = "%s.%d" % (self.full_subnet, access_list[0])
        if debug: print "setting subnet to %s" % self.subnet
        return 1

    def allocate_client(self):
        net = self.subnet
        # Extract the IP leases from the status file
        new_ip=""
        pool=[]
        if debug >= 2: print "Status file:"
        self.read_status()
        for line in self.status:
            line = line.strip()
            if line.startswith(net):
                if debug >= 2: print "  %s" % line
                (ip, common_name, real_addr, date) = line.split(',')
                octet = int(ip.split('.')[-1])
                if common_name == self.common_name and \
                        real_addr.startswith(self.trusted_ip + ":"):
                    # Same user is reconnecting, reuse the IP
                    if debug: print "reconnect for %s" % common_name
                    new_ip = octet
                    break
                pool.append(octet)

        if not new_ip:
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
