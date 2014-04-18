from pprint import pprint
import sys
import libtorrent as lt
from ipaddress import ip_address, AddressValueError
import time

def ips_for_magnet(link, wait=0):
    """Fetches all the IP addresses used to seed a tracker represented by
    a magnet uri.

    Args:
        link -- a valid magnet uri

    Keyword Args:
        wait -- the amount of time to wait and let seeds start responding
                before quiting

    Return:
        A pair of lists, first containing all ipv4 addresses seeding the
        tracker, and second containing all the ipv6 addresses seeding the
        tracker.  Addresses are represented by IPv4Address and IPv6Address
        instances, respectivly.
    """
    # info = lt.parse_magnet_uri(link)
    ses = lt.session()
    params = { 'save_path': '.'}
    handle = lt.add_magnet_uri(ses, link, params)
    handle.set_download_limit(0)

    while not handle.has_metadata():
        print "Fetching metadata"
        time.sleep(1)

    info = handle.get_torrent_info()
    pprint(dir(handle))
    pprint(dir(info))
    pprint(info.web_seeds())
    pprint(info.http_seeds())
    # print handle
    sys.exit()
    # while wait > 0:
    #     time.sleep(1)
    #     wait -= 1

    peer_infos = handle.get_peer_info()
    ipv6_addrs = []
    ipv4_addrs = []
    for pi in peer_infos:
        addr_str, port = pi.ip
        try:
            addr = ip_address(addr_str.decode())
            if addr.version == 4:
                ipv4_addrs.append(addr)
            else:
                ipv6_addrs.append(addr)
        except AddressValueError:
            continue

    return ipv4_addrs, ipv6_addrs

if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description='Fetch IP addresses feeding a magetnet link.')
    parser.add_argument('--v6', action='store_true',
                        help="Print out ipv6 addresses seeding the tracker.")
    parser.add_argument('--v4', action='store_true',
                        help="Print out ipv4 addresses seeding the tracker.")
    parser.add_argument('--secs', type=int, default=0,
                        help="The amount of time to wait and watch for seeders on the tracker.")
    parser.add_argument('--uri', default=None,
                        help="The magetnet uri to fetch a tracker for.  If not provided, STDIN is used.")
    args = parser.parse_args()


    addresses = [args.uri] if args.uri else (a.strip() for a in sys.stdin.readlines())
    all_ip4s = []
    all_ip6s = []
    for addr in addresses:
        ip4s, ip6s = ips_for_magnet(addr, wait=args.secs)
        if args.v4:
            for a in ip4s:
                print a
        if args.v6:
            for a in ip6s:
                print a
