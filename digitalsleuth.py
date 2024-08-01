import requests
from bs4 import BeautifulSoup
import re
import whois
import dns.resolver
import shodan
import json
from datetime import datetime
import time
import os
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

class DigitalSleuth:
    def __init__(self):
        self.target = ""
        self.api_key = ""
        self.shodan_api = None

    def set_target(self, target):
        self.target = target

    def set_shodan_api_key(self, api_key):
        self.api_key = api_key
        self.shodan_api = shodan.Shodan(self.api_key)

    def gather_web_info(self):
        url = f"http://{self.target}"
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            title = soup.title.string if soup.title else "No title found"
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', response.text)
            
            return {
                "title": title,
                "emails": emails,
                "status_code": response.status_code
            }
        except requests.RequestException as e:
            return {"error": str(e)}

    def get_whois_info(self):
        try:
            domain_info = whois.whois(self.target)
            return {
                "registrar": domain_info.registrar,
                "creation_date": domain_info.creation_date,
                "expiration_date": domain_info.expiration_date
            }
        except Exception as e:
            return {"error": str(e)}

    def get_dns_info(self):
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            return [rdata.address for rdata in answers]
        except Exception as e:
            return {"error": str(e)}

    def get_shodan_info(self):
        try:
            results = self.shodan_api.search(self.target)
            return {
                "total_results": results['total'],
                "vulns": [item.get('vulns', []) for item in results['matches']]
            }
        except Exception as e:
            return {"error": str(e)}

    def analyze(self):
        print(f"\n{Fore.CYAN}Analyzing {Fore.YELLOW}{self.target}{Fore.CYAN}...")
        
        web_info = self.gather_web_info()
        print(f"{Fore.GREEN}Web information gathered.")
        
        whois_info = self.get_whois_info()
        print(f"{Fore.GREEN}WHOIS information retrieved.")
        
        dns_info = self.get_dns_info()
        print(f"{Fore.GREEN}DNS information collected.")
        
        shodan_info = self.get_shodan_info()
        print(f"{Fore.GREEN}Shodan information acquired.")

        vulnerabilities = []
        if web_info.get("status_code") == 200:
            vulnerabilities.append("Website is publicly accessible")
        
        # Convert datetime objects to strings
        if isinstance(whois_info.get("creation_date"), datetime):
            whois_info["creation_date"] = whois_info["creation_date"].isoformat()
        elif isinstance(whois_info.get("creation_date"), list):
            whois_info["creation_date"] = [d.isoformat() if isinstance(d, datetime) else d for d in whois_info["creation_date"]]
        
        if isinstance(whois_info.get("expiration_date"), datetime):
            whois_info["expiration_date"] = whois_info["expiration_date"].isoformat()
        elif isinstance(whois_info.get("expiration_date"), list):
            whois_info["expiration_date"] = [d.isoformat() if isinstance(d, datetime) else d for d in whois_info["expiration_date"]]
        
        if whois_info.get("expiration_date"):
            try:
                if isinstance(whois_info["expiration_date"], list):
                    expiration_date = datetime.fromisoformat(whois_info["expiration_date"][0])
                else:
                    expiration_date = datetime.fromisoformat(whois_info["expiration_date"])
                if (expiration_date - datetime.now()).days < 30:
                    vulnerabilities.append("Domain expiration is approaching")
            except (ValueError, TypeError):
                pass  # If the date string is invalid or None, we'll skip this check
        
        if shodan_info.get("total_results", 0) > 0:
            vulnerabilities.append(f"Found {shodan_info['total_results']} open ports/services")

        return {
            "web_info": web_info,
            "whois_info": whois_info,
            "dns_info": dns_info,
            "shodan_info": shodan_info,
            "vulnerabilities": vulnerabilities
        }

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""{Fore.CYAN}
    ____  _       _ _        _ _____ _            _   _     
   |  _ \(_)     (_) |      | /  ___| |          | | | |    
   | | | |_  __ _ _| |_ __ _| \ `--.| | ___ _   _| |_| |__  
   | | | | |/ _` | | __/ _` | |`--. \ |/ _ \ | | | __| '_ \ 
   | |/ /| | (_| | | || (_| | /\__/ / |  __/ |_| | |_| | | |
   |___/ |_|\__, |_|\__\__,_|_\____/|_|\___|\__,_|\__|_| |_|
             __/ |                                          
            |___/                                           
    """
    print(banner)
    print(f"{Fore.YELLOW}Welcome to DigitalSleuth - Your OSINT Aggregator Tool")
    print(f"{Fore.YELLOW}-----------------------------------------------------")

def main_menu():
    sleuth = DigitalSleuth()
    
    while True:
        clear_screen()
        print_banner()
        print(f"\n{Fore.CYAN}Main Menu:")
        print(f"{Fore.WHITE}1. Set target domain")
        print(f"{Fore.WHITE}2. Set Shodan API key")
        print(f"{Fore.WHITE}3. Run analysis")
        print(f"{Fore.WHITE}4. Exit")
        
        choice = input(f"\n{Fore.GREEN}Enter your choice (1-4): ")
        
        if choice == '1':
            target = input(f"{Fore.YELLOW}Enter the target domain: ")
            sleuth.set_target(target)
            print(f"{Fore.GREEN}Target set to: {Fore.WHITE}{target}")
            time.sleep(1)
        elif choice == '2':
            api_key = input(f"{Fore.YELLOW}Enter your Shodan API key: ")
            sleuth.set_shodan_api_key(api_key)
            print(f"{Fore.GREEN}Shodan API key set successfully")
            time.sleep(1)
        elif choice == '3':
            if not sleuth.target:
                print(f"{Fore.RED}Please set a target domain first.")
                time.sleep(1)
                continue
            if not sleuth.api_key:
                print(f"{Fore.RED}Please set your Shodan API key first.")
                time.sleep(1)
                continue
            
            results = sleuth.analyze()
            
            clear_screen()
            print_banner()
            print(f"\n{Fore.CYAN}Analysis Results:")
            print(f"{Fore.WHITE}{json.dumps(results, indent=2)}")
            
            save_option = input(f"\n{Fore.YELLOW}Do you want to save these results to a file? (y/n): ")
            if save_option.lower() == 'y':
                filename = f"digital_sleuth_report_{sleuth.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"{Fore.GREEN}Results saved to {Fore.WHITE}{filename}")
            
            input(f"\n{Fore.YELLOW}Press Enter to return to the main menu...")
        elif choice == '4':
            print(f"{Fore.CYAN}Thank you for using DigitalSleuth. Goodbye!")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()