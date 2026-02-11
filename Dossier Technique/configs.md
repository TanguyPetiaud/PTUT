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
VLAN 23, testVLAN, tagged traffic on Interface 1, 192.168.0.10/24

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



# ... - step 11
