import ipaddress
import random
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

class FirewallRule:
    def __init__(self, direction, action, ip_pattern, port_pattern, flag=None):
        self.direction = direction.lower()
        self.action = action.lower()
        self.ip_pattern = ip_pattern
        self.port_pattern = port_pattern
        self.flag = flag

    def matches(self, packet):
        if self.direction != packet['direction']:
            return False
        if self.flag is not None and self.flag != packet['flag']:
            return False
        if self.ip_pattern != '*':
            try:
                net = ipaddress.ip_network(self.ip_pattern, strict=False)
                ip = ipaddress.ip_address(packet['ip'])
                if ip not in net:
                    return False
            except ValueError:
                return False
        if self.port_pattern != '*':
            if '-' in self.port_pattern:
                start, end = map(int, self.port_pattern.split('-'))
                if not (start <= packet['port'] <= end):
                    return False
            else:
                if int(self.port_pattern) != packet['port']:
                    return False
        return True

    def __str__(self):
        return f"{self.direction.upper()} | {self.action.upper()} | IP: {self.ip_pattern} | Port: {self.port_pattern} | Flag: {self.flag or 'Any'}"

class Firewall:
    def __init__(self):
        self.rules = []
        self.log = []

    def add_rule(self, direction, action, ip_pattern, port_pattern, flag=None):
        rule = FirewallRule(direction, action, ip_pattern, port_pattern, flag)
        self.rules.append(rule)

    def check_packet(self, packet):
        for idx, rule in enumerate(self.rules, 1):
            if rule.matches(packet):
                self.log_packet(packet, rule.action, idx)
                return rule.action, idx
        # Default policy: drop
        self.log_packet(packet, 'drop', None)
        return 'drop', None

    def log_packet(self, packet, action, rule_num):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp} | Packet: {packet} -> {action.upper()} (Rule {rule_num if rule_num else 'Default'})"
        self.log.append(entry)

class TrafficSimulator:
    def __init__(self, firewall):
        self.firewall = firewall

    def generate_random_ip(self):
        return ".".join(str(random.randint(0, 255)) for _ in range(4))

    def generate_packet(self):
        direction = random.choice(['in', 'out'])
        ip = self.generate_random_ip()
        port = random.choice([22, 80, 443, 8080, 53, random.randint(1024, 65535)])
        flag = random.choice([None, 'established'])
        return {'direction': direction, 'ip': ip, 'port': port, 'flag': flag}

    def simulate_packet(self):
        packet = self.generate_packet()
        action, rule_num = self.firewall.check_packet(packet)
        return packet, action, rule_num

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulated Firewall GUI")

        self.firewall = Firewall()
        self.simulator = TrafficSimulator(self.firewall)

        self.setup_ui()

    def setup_ui(self):
        # Rules frame
        rules_frame = ttk.LabelFrame(self.root, text="Firewall Rules")
        rules_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.rules_listbox = tk.Listbox(rules_frame, width=80, height=10)
        self.rules_listbox.grid(row=0, column=0, columnspan=4, pady=5)

        ttk.Label(rules_frame, text="Direction (in/out):").grid(row=1, column=0)
        self.direction_var = tk.StringVar(value="in")
        ttk.Entry(rules_frame, textvariable=self.direction_var, width=10).grid(row=1, column=1)

        ttk.Label(rules_frame, text="Action (allow/drop):").grid(row=1, column=2)
        self.action_var = tk.StringVar(value="allow")
        ttk.Entry(rules_frame, textvariable=self.action_var, width=10).grid(row=1, column=3)

        ttk.Label(rules_frame, text="IP Pattern (* or CIDR):").grid(row=2, column=0)
        self.ip_var = tk.StringVar(value="*")
        ttk.Entry(rules_frame, textvariable=self.ip_var, width=15).grid(row=2, column=1)

        ttk.Label(rules_frame, text="Port Pattern (*, single or range):").grid(row=2, column=2)
        self.port_var = tk.StringVar(value="*")
        ttk.Entry(rules_frame, textvariable=self.port_var, width=15).grid(row=2, column=3)

        ttk.Label(rules_frame, text="Flag (None or 'established'):").grid(row=3, column=0)
        self.flag_var = tk.StringVar(value="")
        ttk.Entry(rules_frame, textvariable=self.flag_var, width=15).grid(row=3, column=1)

        ttk.Button(rules_frame, text="Add Rule", command=self.add_rule).grid(row=3, column=3)

        # Simulation frame
        sim_frame = ttk.LabelFrame(self.root, text="Traffic Simulation")
        sim_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        ttk.Button(sim_frame, text="Simulate Random Packet", command=self.simulate_packet).grid(row=0, column=0, pady=5)

        self.sim_output = scrolledtext.ScrolledText(sim_frame, width=80, height=15, state='disabled')
        self.sim_output.grid(row=1, column=0)

        # Log frame
        log_frame = ttk.LabelFrame(self.root, text="Firewall Log")
        log_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        self.log_output = scrolledtext.ScrolledText(log_frame, width=80, height=10, state='disabled')
        self.log_output.grid(row=0, column=0)

    def add_rule(self):
        direction = self.direction_var.get().strip().lower()
        action = self.action_var.get().strip().lower()
        ip_pattern = self.ip_var.get().strip()
        port_pattern = self.port_var.get().strip()
        flag = self.flag_var.get().strip() or None

        if direction not in ('in', 'out'):
            messagebox.showerror("Error", "Direction must be 'in' or 'out'.")
            return
        if action not in ('allow', 'drop'):
            messagebox.showerror("Error", "Action must be 'allow' or 'drop'.")
            return

        try:
            if ip_pattern != '*':
                ipaddress.ip_network(ip_pattern, strict=False)
            if port_pattern != '*':
                if '-' in port_pattern:
                    start, end = port_pattern.split('-')
                    if not (start.isdigit() and end.isdigit()):
                        raise ValueError
                else:
                    if not port_pattern.isdigit():
                        raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid IP or Port pattern.")
            return

        self.firewall.add_rule(direction, action, ip_pattern, port_pattern, flag)
        self.rules_listbox.insert(tk.END, f"{direction.upper()} | {action.upper()} | IP: {ip_pattern} | Port: {port_pattern} | Flag: {flag or 'Any'}")

        # Clear inputs
        self.ip_var.set('*')
        self.port_var.set('*')
        self.flag_var.set('')

    def simulate_packet(self):
        packet, action, rule_num = self.simulator.simulate_packet()
        msg = f"Packet: {packet} -> {action.upper()} (Rule {rule_num if rule_num else 'Default'})\n"
        self.sim_output.config(state='normal')
        self.sim_output.insert(tk.END, msg)
        self.sim_output.see(tk.END)
        self.sim_output.config(state='disabled')

        # Update log display
        self.log_output.config(state='normal')
        self.log_output.delete(1.0, tk.END)
        self.log_output.insert(tk.END, "\n".join(self.firewall.log[-50:]))
        self.log_output.see(tk.END)
        self.log_output.config(state='disabled')

def main():
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
