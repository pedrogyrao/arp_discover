from tqdm import tqdm
from arp import scan


def print_result(all_answers):
    print('IP\t\t\tMAC')
    print('----------------------------------------')
    for answers in all_answers:
        for ip, mac in answers:
            print(f'{ip}\t\t{mac}')


if __name__ == '__main__':
    all_answers = []
    for i in tqdm(range(255)):
        dst_ip = f'192.168.0.{i}'
        answers = scan(
            src_mac='44:1c:a8:bf:b0:83',
            src_ip='192.168.0.6',
            dst_ip=dst_ip,
            timeout=0.5)

        if len(answers) > 0:
            all_answers.append(answers)

    if len(all_answers) > 0:
        print_result(all_answers)
    else:
        print('No ip/mac found!')
