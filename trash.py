def udp_create_announce_request(connection_id, torrent_hash):

    # Taken from http://www.bittorrent.org/beps/bep_0015.html
    action = 0x1 #action (1 = announce)
    transaction_id = scraper.udp_get_transaction_id()
    buf = struct.pack("!q", connection_id) #first 8 bytes is connection id
    buf += struct.pack("!i", action) #next 4 bytes is action
    buf += struct.pack("!i", transaction_id) #followed by 4 byte transaction id

    # Add torrent hash
    hex_repr = binascii.a2b_hex(torrent_hash)
    buf += struct.pack("!20s", hex_repr)

    peer_id = '-PS1234-' + ''.join(chr(random.randint(0,255)) for i in range(12))

    buf += struct.pack("!20s", peer_id) # Add peer_id

    buf += struct.pack("!q", 0) # download value
    buf += struct.pack("!q", 0) # left value
    buf += struct.pack("!q", 0) # uploaded value

    buf += struct.pack("!i", 0) # event value
    buf += struct.pack("!i", 0) # ip address value value
    buf += struct.pack("!i", 0) # key value value
    buf += struct.pack("!i", 50) # num_want value
    buf += struct.pack("!h", 9999) # port value

    return (buf, transaction_id)


def udp_create_announce_response(buf, sent_transaction_id, torrent_hash):
    buf_len = len(buf)
    if buf_len < 16:
        raise RuntimeError("Wrong response length while scraping: %s" % len(buf))
    action = struct.unpack_from("!i", buf)[0] #first 4 bytes is action

    # next 4 bytes is transaction id
    res_transaction_id = struct.unpack_from("!i", buf, 4)[0]
    if res_transaction_id != sent_transaction_id:
        raise RuntimeError("Transaction ID doesnt match in scrape response! Expected %s, got %s" % (sent_transaction_id, res_transaction_id))

    if action == 0x1:
        offset = 8; #next 4 bytes after action is transaction_id, so data doesnt start till byte 8
        seeds = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        complete = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        leeches = struct.unpack_from("!i", buf, offset)[0]
        offset += 4

        print binascii.b2a_uu(buf)

        while offset < buf_len:
            pass

        return None
    else:
        #an error occured, try and extract the error string
        error = struct.unpack_from("!s", buf, 8)
        raise RuntimeError("Error while scraping: %s" % error)


def udp_announce(tracker, torrent_hash):
    parsed_tracker= urlparse(tracker)
    transaction_id = "\x00\x00\x04\x12\x27\x10\x19\x70"
    connection_id = "\x00\x00\x04\x17\x27\x10\x19\x80"
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(8)
    conn = (socket.gethostbyname(parsed_tracker.hostname), parsed_tracker.port)

    #Get connection ID
    req, transaction_id = scraper.udp_create_connection_request()
    sock.sendto(req, conn);
    buf = sock.recvfrom(2048)[0]
    connection_id = scraper.udp_parse_connection_response(buf, transaction_id)

    #Scrape away
    req, transaction_id = udp_create_announce_request(connection_id, torrent_hash)
    sock.sendto(req, conn)
    buf = sock.recvfrom(2048)[0]
    return udp_create_announce_response(buf, transaction_id, torrent_hash)
