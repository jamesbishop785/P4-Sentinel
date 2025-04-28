from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import time
from colorama import Fore, Style, init
from datetime import datetime

init()

class RateLimiterController:
    def __init__(self, switch_name='s1', thrift_port=9090):
        self.switch_name = switch_name 
        self.thrift_port = thrift_port  
        self.controller = None          
        self.attack_start_time = None   
        self.attack_history = []
        self.attack_drop_total = 0
        
    def connect(self):
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        print(f"Connected to switch {self.switch_name} on port {self.thrift_port}") # Notifies User They have Successfully Connected to Switch and what Port it is Running on
        
    def disconnect(self):
        if self.controller:
            print(f"Disconnected from switch {self.switch_name}")  # Notifies User They Have Disconnected From Switch
            
    def read_counters(self, index=None):
        if not self.controller:
            raise RuntimeError("Not connected to switch")   # Notifies User if They are Not Connected to the Switch
            
        results = []    # New Results List
        
        for i in range(REGISTER_SIZE):  # Scans Indecies (0-1024)
            try:
                forward = self.controller.register_read("packet_counter", i)    # Reads Foward Packets
                drops = self.controller.register_read("drop_counter", i)        # Reads Dropped Packets
                if forward > 0 or drops > 0:
                    results.append({
                        'index': i,         # Active Indecies
                        'forward': forward, # Forwarded Packets
                        'drops': drops      # Dropped Packets
                    })
            except:
                continue    # Skips Non-Active Indexes
                    
        return results      # Lists Active Flows
    
    def detect_ddos(self, counters):
        current_time = datetime.now().strftime("%H:%M:%S")  # Get Time for Attack History
        total_drops = sum(c['drops'] for c in counters)     # Total Number of Dropped Packets
        total_forward = sum(c['forward'] for c in counters) # Total Number of Forward Packets
        
        if total_drops > 0: # DDoS Attack
            if not self.attack_start_time:  # Checks for Ongoing Attacks
                self.attack_start_time = current_time   # Records Current Attack Time
                self.attack_drop_total = total_drops    # Records Total Packets Dropped for Current Attack
                self.attack_history.append({            # Adds New Attack History Entry
                    'start': current_time,              # Start Time of Attack
                    'total_drops': total_drops          # Total Number of Drops
                })
            else:
                self.attack_drop_total += total_drops                           # Executes When an Attack is Already Ongoing
                self.attack_history[-1]['total_drops'] = self.attack_drop_total # Updates Latest Attack Record
            return True, total_forward, total_drops                             # True = Attack Ongoing, Displays total_forward and total_drops
        else:
            if self.attack_start_time:
                self.attack_history[-1]['end'] = current_time   # Update Ongoing to End Timestamp
                self.attack_start_time = None                   # Clear Attack
                self.attack_drop_total = 0                      # Reset Drop Counter
            return False, total_forward, total_drops            # Return to Normal Status
    
    def monitor_loop(self, interval=2):
        try:
            print(f"Monitoring rate limiter with threshold {THRESHOLD} pps")
            print("Press Ctrl+C to stop")
            
            while True:
                current_time = datetime.now().strftime("%H:%M:%S")              # Get Current Time
                counters = self.read_counters()                                 # Reads Network Traffic
                is_attack, total_fwd, total_drp = self.detect_ddos(counters)    # Analyses Counters  
                
                print("\033[H\033[J", end="") # ANSI Escape (Clears Terminal Space in Linux)

                print(f"Current Time: {current_time}")  # Displays Current Time
                
                if is_attack:
                    print(f"\nPOTENTIAL DDoS DETECTED")                                                 # Tells User a DDoS Attack is Occuring
                    print(f"Forwarded: {total_fwd} packets")                                            # Shows Number of Packets Forwarding
                    print(f"Dropped: {Fore.RED}{total_drp}{Style.RESET_ALL} packets")   # Shows Number of Packets Dropped During the Ongoing Attack
                    print(f"Attack Ratio: {total_drp/(total_fwd+total_drp):.1%}")                       # Displays the Percentage of Packets on the Network are being Dropped compared to Forwarded
                else:
                    print(f"\nSystem Normal")                   # Tells User that No DDoS Attack
                    print(f"Forwarded: {total_fwd} packets")    # Prints Total Number of Forwarded Packets
                
                print("\nActive Flows:")
                print(f"{'Index':<8}{'Forward':<12}{'Drops':<12}{'Status':<15}")         # Table Header Set-Up
                for c in sorted(counters, key=lambda x: x['drops'], reverse=True)[:10]:  # Orders Active Flows by Highest Drop Count (Top 10)
                    status = f"{Fore.RED}BLOCKED{Style.RESET_ALL}" if c['drops'] > 0 else f"{Fore.GREEN}ALLOWED{Style.RESET_ALL}"   # Status Shows "BLOCKED" in Red in Drops Happen and "ALLOWED" in Green if no Drops 
                    print(f"{c['index']:<8}{c['forward']:<12}{c['drops']:<12}{status:<15}") # Data Display
                
                if self.attack_history:     # Checks if any Recorded Attacks
                    print("\nAttack History:")    # Outputs Attack History in Terminal
                    for attack in self.attack_history[-3:]:     # Gets last 3 Attack (Most Recent First)
                        end = attack.get('end', 'Ongoing')      # Retrieves Attack End Time or if it Carries on show "Ongoing"
                        print(f"- {attack['start']} to {end}: {attack['total_drops']} packets dropped") # Display Attack Event Info
                
                time.sleep(interval)    # Delays 2 Secs for Effiecient CPU Usage
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped")

# Same Contants in P4 Programme
THRESHOLD = 100
TIME_WINDOW = 1
REGISTER_SIZE = 1024

if __name__ == "__main__":
    controller = RateLimiterController()
    
    try:
        controller.connect()
        controller.monitor_loop()
    finally:
        controller.disconnect()