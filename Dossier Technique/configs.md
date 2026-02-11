# In this file
A brief description of the content of a configuration file, with the changes made since the last version.
All versions are listed in order of generation.

The config files are included in this repo.


# Base configuration
This is the basic configuration file, exactly as it is after the initial setup wizard.
DHCP has not been enabled on the internal interface.
The feature key provided by the IUT has been activated.


# Interface configuration - step 1
## Changes
Interface 1 was changed:
- Name: Trusted -> Inside
- Mode: Trusted -> Optional
- IPv4 address: 10.0.1.1/24 -> 192.168.0.1/24
- Description: / -> The interface for local network

## Effects
### Line ~750
It seems the changes have affected some global objects. For some reason diff seems to see some shuffling, namely the "address group" "Any" has swapped places with "dnat.from.3". It seems that these changes are purely cosmetic, the content of these groups is the same.
I should be careful about nat groups going forward.

### Line ~17080
A whole alias section was removed. It covered the old interface configuration, for the interface itself.

### Line ~17270
Three alias sections were removed. They covered NAT information (?).

### Line ~17540
The new interface information was readded. It seems it was added at the end of the alias list, indicating the alias list order has no incidence on its function.

The NAT aliases were also readded here. No change was made, other than removing the description tag.

Concerning the interface information, we can observe the following structure:
<alias>
    <name>yes</name>
    <description>yes</description>
    <property>A number. Not unique, thus not the interface ID. Its type?</property>
    <alias-member-list>
        <alias-member>
            <type>A number.</type>
            <user>A string ("Any").</user>
            <address>A string ("Any").</address>
            <interface>An interface name.</interface>
        </alias-member>
        There could be more aliases here?
    </alias-member-list>
</alias>
An empty tag can be used: <name/>

### Line ~18120
An interface tag was modified, changing the name and description tags.
A little lower, the "if-property" and "ip" tags were changed, and an "ip-node-type" tag was added.
It seems "if-property" corresponds to the interface type:
1 -> Trusted
3 -> Optional
These do not align with the order in the web interface.
The next diff should focus on those, unless I can find their meaning online.
The structure of the interface tag should be analyzed, to find any unknown tags for analysis.



# Interface configuration - step 2
## Changes
The interface 1 was changed:
- Type: Optional -> Custom

## Effect
"if-property" for the interface changed from 3 (Optional) to 8 (Custom).



# Interface configuration - step 3
## Changes
The interface 1 was changed:
- Type: Custom -> Bridge
Note that a bridge interface has no parameters.
My understanding is all bridge interfaces work as a basic switch - security policies are ignored and trafic is switched.

## Effects
### Line ~17480
Alias configuration:
The entire alias tag for the interface was removed.
This means, as expected from above, that a bridge interface has no parameters.

### Line ~18120
Interface configuration:
"if-property" was changed from 8 (Custom) to 6 (Bridge).
The ip tag remains, but was changed to 0.0.0.0

### Line ~18160
Interface configuration (presumably):
A "dhcp-server" tag was removed. The only parameter, "server-type", was 0. I assume this meant disabled. To check later.



# Interface configuration - step 4
## Changes
The interface 1 was changed:
- Type: Bridge -> VLAN

## Effects
### Line ~18110
Interface configuration:
"if-property" was changed from 6 (Bridge) to 5 (VLAN).



# Interface configuration - step 5
## Changes
The interface 1 was changed:
- Type: VLAN -> Disabled

## Effects
### Line ~18110
Interface configuration, physical interface:
An "enabled" tag was changed from 1 to 0.



# Interface configuration - step 6
## Changes
The interface 1 was changed:
- Type: Disabled -> Trusted
- Address: 0.0.0.0/24 -> 192.168.0.5/25

## Effects
### Line ~17520
Alias configuration:
A new alias was added (at the end).
It contains the interface name, description, "property" (2) and alias member.

### Line ~18115
Interface configuration:
"enabled" tag: 0 -> 1
"if-property" tag: 5 (could be anything) -> 1 (Trusted)
ip and netmask tags changed.

### Line ~18140
Interface configuration:
dhcp server tag added, type tag is 0.



# Interface configuration - step 7
## Changes
Interface 1 was changed: DHCP relay was activated, and 2 servers were added: 192.168.0.3, 192.168.0.4

## Effects
### Line ~18160
Interface configuration (presumably):
"server-type" tag was changed from 0 (disabled) to 2 (relay) (presumably).
A "relay-server-ip" tag was added for each server:
<relay-server-ip>192.168.0.4</relay-server-ip>



# Interface configuration - step 8
## Changes
Interface 1 was changed: DHCP server was activated, with the following parameters:
Pool: 192.168.0.6 - 192.168.0.25
Reserved addresses: 192.168.0.10, 192.168.0.11, 192.168.0.15
192.168.0.10, Server1, 01:23:45:67:89:ab
192.168.0.11, Server2, ba:98:76:54:32:10
192.168.0.15, Server, 00:11:22:33:44:55
Use the interface address for gateway.

## Effects
### Line ~18160
As expected, dhcp server type tag changed from 2 to 1.
An address pool list tag was added, with corresponding information.
Some empty options tags were added (domain name, dns server list...).



# Interface configuration - step 9
## Changes
The interface 1 was changed:
- Gateway address: FW's address -> 192.168.0.4

## Effects
### Line ~18190
A "gateway-ip" tag was added in the dhcp server options.



# VLAN configuration - step 10
## Changes
The interface 1 was changed:
- Type: Trusted -> VLAN
A VLAN was created:
VLAN 23, testVLAN, type Trusted, tagged traffic on Interface 1, 192.168.0.10/24

## Effects
### Line ~17525
Alias configuration:
Changed the name of the interface to the name of the VLAN, in the alias definition and the alias member list.

### Line ~18130
Interface configuration:
Changed type from 1 (Trusted) to 5 (VLAN).
Changed address to 0.0.0.0/24.

### Line ~18160
Removed dhcp configuration from the interface.
Added a new interface tag, for the VLAN. A VLAN is thus considered as an interface.
Tags:
- Property: 0
- Contains an if-item-list tag, containing the VLAN number, property, interface names, ip...



# VLAN configuration - step 11
## Changes
Added a second VLAN:
VLAN 56, testVLAN2, type "Optional", untagged traffic on interface 1, 192.168.1.11/24
"Apply firewall policies to intra-VLAN traffic" option enabled.

## Effects
### Line ~17500
A new alias was added. These aliases are actually just the alias objects used by the UTM. To verify later, but I believe this solves the alias analysis problem.

### Line ~18200
As expected, a new interface section was added for the new VLAN.
To note, a special "vlan-if" tag was used to define this interface.



# Aliases - step 12
## Changes
Added a new alias:
testAddress, with short description, two members: an IPv4 (192.168.11.22) and an FQDN (perdu.com)

## Effects
### Line ~750
A new "address group" was added for each alias, with property 0.
There names were "[alias name].[item number].alm".
One was type 8 (FQDN), the other was type 1 (IPv4 host).

### Line ~17500
A new alias tag was added, with two "alias-member", their "address" being the name of the aforementioned "address group" objects.



# Aliases - step 13
## Changes
Added a new item to the alias from the previous step: an IPv4 network (172.16.33.0/24).
Removed the FQDN member from the alias.

## Effects
### Line ~750
The address-group was changed, replacing the infos for the FQDN to those for the network.
In essence, the address-groups (related to aliases) represent the items in the list of the alias. They only exist to support the alias definition.



# NAT - step 14
## Changes
Added an address range to NAT: 10.1.0.0/24 to any external interface, in position 2.

## Effects
### Line ~750
A new address-group was added, with the name "dnat.from.4", and property 16.
The previous dnat.from.x were moved, to reflect the new order (2 became 3, 3 became 4 and the new one became the new 2).

### Line ~19500
A new dnat tag was added to the dnat-list, to reflect the new count (4).

I assume the firewall filter definition will include a reference to dnat somewhere.
For some odd reason, it seems alias definitions get shuffled around with configuration modifications. Maybe (probably) a diff quirk. Let's pray alias definition order isn't important.



# NAT - step 15
## Changes
Added a new 1to1 NAT definition: 192.168.11.12 -> 172.23.200.19

## Effects
### Line ~850
One address-group was added for each address (internal and external), called Nat.[x].1nat and Real.[x]1nat.

### Line ~19500
"one-to-one-nat-list" was modified to include a new "one-to-one-nat" item, with a real-address, a nat-address and interface tags (with the names).


