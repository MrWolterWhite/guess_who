import pyshark
import requests
  

class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """        
                pcap_path (string): path to a pcap file
        """
        self.path = pcap_path
        self.packets = []
        with pyshark.FileCapture(pcap_path) as sniffed_pacs:
            for sniffed_pac in sniffed_pacs:
                self.packets.append(sniffed_pac)

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        ips = []
        for packet in self.packets:
            if 'ip' in packet:
                ip = packet['ip']
                if 'eth' in packet:
                    eth = packet['eth']
                else:
                    eth = None

                if ip.src not in ips and (eth and eth.src != "ff:ff:ff:ff:ff:ff"):
                    ips.append(ip.src)
                if ip.dst not in ips and (eth and eth.dst != "ff:ff:ff:ff:ff:ff"):
                    ips.append(ip.dst)

        return ips
    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        macs = []
        for packet in self.packets:
            if 'eth' in packet:
                eth = packet['eth']
                if eth.src not in macs and eth.src != "ff:ff:ff:ff:ff:ff":
                    macs.append(eth.src)
                if eth.dst not in macs and eth.dst != "ff:ff:ff:ff:ff:ff":
                    macs.append(eth.dst)
        return macs
    
    def get_vendor_from_mac(mac_address):
        #Get vendor's name using API

        url = "https://api.macvendors.com/"

        response = requests.get(url+mac_address, timeout=3)
        if not response or response.status_code != 200:
            return "Unknown"
        return response.content.decode()

    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        for packet in self.packets:
            if 'eth' in packet and mac!="ff:ff:ff:ff:ff:ff":
                eth = packet['eth']
                if 'ip' in packet:
                    ip = packet['ip']
                else:
                    ip = None
                if eth.dst == mac:
                    if ip:
                        if 'icmp' in packet and packet['icmp'].type in ["0","8"]:
                            return {"MAC": mac, "IP": ip.dst, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(mac), "DEFAULT_TTL":packet["ip"].ttl}
                        else:
                            return {"MAC": mac, "IP": ip.dst, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(mac), "DEFAULT_TTL":-1}
                        
                    else:
                        return {"MAC": mac, "IP": "Unknown", "VENDOR": AnalyzeNetwork.get_vendor_from_mac(mac), "DEFAULT_TTL":-1}
                if eth.src == mac:
                    if ip:
                        if 'icmp' in packet and packet['icmp'].type in ["0","8"]:
                            return {"MAC": mac, "IP": ip.src, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(mac), "DEFAULT_TTL":packet["ip"].ttl}
                        else:  
                            return {"MAC": mac, "IP": ip.src, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(mac), "DEFAULT_TTL":-1}
                    else:
                        return {"MAC": mac, "IP": "Unknown", "VENDOR": AnalyzeNetwork.get_vendor_from_mac(mac), "DEFAULT_TTL":-1}

    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        for packet in self.packets:
            if 'ip' in packet:
                ip_pac = packet['ip']
                if 'eth' in packet:
                    eth = packet['eth']
                else:
                    eth = None

                if ip_pac.dst == ip:
                    if eth and eth.dst!="ff:ff:ff:ff:ff:ff":
                        if 'icmp' in packet and packet['icmp'].type in ["0","8"]:
                            return {"MAC": eth.dst, "IP": ip, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.dst), "DEFAULT_TTL":packet["ip"].ttl}
                        else:
                            return {"MAC": eth.dst, "IP": ip, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.dst), "DEFAULT_TTL":-1}
                    elif not eth:
                        return {"MAC": "Unknown", "IP": ip, "VENDOR": "Unknown", "DEFAULT_TTL":-1}
                if ip_pac.src == ip:
                    if eth and eth.src!="ff:ff:ff:ff:ff:ff":
                        if 'icmp' in packet and packet['icmp'].type in ["0","8"]:
                            return {"MAC": eth.src, "IP": ip, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.src), "DEFAULT_TTL":packet["ip"].ttl}
                        else:
                            return {"MAC": eth.src, "IP": ip, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.src), "DEFAULT_TTL":-1}
                    elif not eth:
                        return {"MAC": "Unknown", "IP": ip, "VENDOR": "Unknown", "DEFAULT_TTL":-1}
    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        
        info_list = [] #The returned list
        mac_list = [] #To keep track of the computers we added
        for packet in self.packets:
            if 'eth' in packet:
                eth = packet['eth']
                if 'ip' in packet:
                    ip = packet['ip']
                else:
                    ip = None

                if eth.src not in mac_list and eth.src!="ff:ff:ff:ff:ff:ff":
                    if ip:
                        if 'icmp' in packet and packet['icmp'].type in ["0","8"]:
                            info_list.append({"MAC": eth.src, "IP": ip.src, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.src), "DEFAULT_TTL":packet["ip"].ttl})
                        else:
                            info_list.append({"MAC": eth.src, "IP": ip.src, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.src), "DEFAULT_TTL":-1})
                    else:
                        info_list.append({"MAC": eth.src, "IP": "Unknown", "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.src), "DEFAULT_TTL":-1})
                    mac_list.append(eth.src)
                if eth.dst not in mac_list and eth.dst!="ff:ff:ff:ff:ff:ff":
                    if ip:
                        if 'icmp' in packet and packet['icmp'].type in ["0","8"]:
                            pass
                        else:
                            info_list.append({"MAC": eth.dst, "IP": ip.dst, "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.dst), "DEFAULT_TTL":-1})
                            mac_list.append(eth.dst)
                    else:
                        info_list.append({"MAC": eth.dst, "IP": "Unknown", "VENDOR": AnalyzeNetwork.get_vendor_from_mac(eth.dst) , "DEFAULT_TTL":-1})
                        mac_list.append(eth.dst)
        return info_list

    def guess_os(self, device_info):
        """returns assumed operating system of a device"""
        if int(device_info["DEFAULT_TTL"]) == 64:
            return ["MacOS","Linux"]
        elif int(device_info["DEFAULT_TTL"]) == 128:
            return ["Windows"]
        elif int(device_info["DEFAULT_TTL"]) == 255:
            return ["Network Device", "Unix System"]
        else:
            return ["Unknown"]
        
    def __repr__(self):
        return f"Network Analyzer for {self.path}"
    def __str__(self):
        return f"NA-{self.path}"
    
def test():
    NA = AnalyzeNetwork("/Users/yoav/Documents/Networking/Guess Who/pcap-01.pcapng")

    ##Get The IPs
    ips = NA.get_ips()
    print("IPs:")
    for ip in ips:
        print(ip)
    if len(ips) == 0:
        print("no ips :(")
    ##
    ##Get MACs

    macs = NA.get_macs()
    print("MACs:")
    for mac in macs:
        print(mac)
    if len(macs) == 0:
        print("no macs :(")
    ##
    ##Get INFOs

    info = NA.get_info()
    print("INFOs:")
    for item in info:
        print(item)
    ##
    ##Get Specific INFOs

    print("Specific INFO:")   
    info = NA.get_info_by_mac("00:0c:29:1d:1e:8f")
    print(info)
    print(f"Guessed OS: {NA.guess_os(info)}")


if __name__ == "__main__":
    test()