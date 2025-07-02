# SimulatedFirewall
Simulated Firewall with GUI

A Python application simulating a basic firewall with rule management, packet traffic simulation, and logging, featuring a user-friendly Tkinter graphical interface.

**Features**

Define firewall rules specifying:

Direction (in or out)

Action (allow or drop)

IP address pattern (wildcard * or CIDR notation)

Port pattern (wildcard *, single port, or range)

Optional TCP flag (e.g., established)

Simulate random network packets with direction, IP, port, and flag

Check packets against firewall rules with first-match policy, default drop

Log all packet decisions with timestamps and rule references

Interactive GUI to add rules, simulate packets, and view logs

**Installation**

Requires Python 3.x.

No external dependencies beyond the Python standard library.

Clone the repository or download the source code.

**Usage**

Run the main script:

bash
python your_firewall_script.py
This will open a GUI window where you can:

Add firewall rules by specifying parameters and clicking Add Rule

Simulate random packets by clicking Simulate Random Packet

View the list of rules and the firewall log in the interface

**Code Structure**

FirewallRule class: Represents a single firewall rule with matching logic

Firewall class: Stores rules and processes packets, maintains log

TrafficSimulator class: Generates random packets for simulation

FirewallGUI class: Tkinter GUI for user interaction

**Example Rule**

Direction: in

Action: allow

IP Pattern: 192.168.1.0/24

Port Pattern: 80

Flag: established

This rule allows incoming established connections on port 80 from the 192.168.1.0/24 subnet.
