# Simple ARP Discover on Windows!

In this project you will find two classes (CommunicationHandler and PacketParser) as well as a scan function.

## PacketParser

The parser holds the data needed to stack Ether and Arp protocols. It's only possible to change mac and ip of its sequence since this project is only intended to execute an ARP Discover.

## CommuncationHandler

This class contains the raw socket used to comunicate, a sniffer to receive the responses and the logic to send and activate the receiver till all the responses arrive.
It, also, contains the necessary logic to identfy from the response the ip and mac of the responder.

## scan function

This function uses:

1. the PacketParser to create a packet using a source mac address, a source ip and a destination ip;
1. the CommuncationHandler to send the packet and wait for the answers.

## run function

The run functions calls the scan function for each IP from 192.168.0.0 to 192.168.0.255.

## To Run the Project

First clone this repo:

```bash
git clone https://github.com/pedrogyrao/arp_discover.git
cd arp_discover
```

Then meet the requirements:

This application runs on Windows (only). To run it you will need to install python3.7 and the requirements contained in the requirements.txt as well as [WinPcap_4_1_3](https://www.winpcap.org/install/default.htm).

To install the requirements:
```bash
pip install -r requirements.txt
```

In *run.py* Change the src_mac and the src_ip to your own:

```python
if __name__ == '__main__':
    all_answers = []
    for i in tqdm(range(255)):
        dst_ip = f'192.168.0.{i}'
        answers = scan(
            src_mac='44:1c:a8:bf:b0:83',
            src_ip='192.168.0.6',
            dst_ip=dst_ip,
            timeout=0.5)
```

To finish:

```bash
python run.py
```

The result will be something as follows!

```bash
100%|███████████████████████████████████████| 255/255 [02:14<00:00,  1.89it/s]
IP                      MAC
----------------------------------------
192.168.0.1             18:9c:27:50:55:87
192.168.0.2             58:d9:c3:cf:b8:2b
192.168.0.3             f8:1f:32:f1:cc:9a
192.168.0.8             dc:53:60:4e:bb:5f
192.168.0.252           00:00:ca:01:02:03
```

-------
*Pedro Gyrão and Rafael Lima*
