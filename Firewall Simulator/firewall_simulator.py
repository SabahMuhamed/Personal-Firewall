import random 

def generate_random_ip():
    return (f"192.168.1.{random.randint(1,20)}")

def check_firewall_rules(ip,rules):
    for rule_ip,action in rules.items():
        if ip in rule_ip:
           return action
    return "allow"


def main():
    firewall_rules = {
        "192.168.1.1" : "block",
        "192.168.1.5" : "block",
        "192.168.1.8" : "block",
        "192.168.1.14" : "block",
        "192.168.1.13" : "block",
        "192.168.1.9" : "block",
        "192.168.1.12" : "block",
        "192.168.1.19" : "block",
    }

    for _ in range(12):
        ip_address = generate_random_ip()
        action = check_firewall_rules(ip_address,firewall_rules)
        print(f"IP : {ip_address} , Action : {action}")

if __name__ == "__main__" :
   main() 

