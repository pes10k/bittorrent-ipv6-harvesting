import requests
import re

magnet_pattern = re.compile(r'magnet:.*?["\' ]', re.U | re.I)

def magnet_uris_on_url(url):
    """Fetches all magent uris listed in HTML fetched from a given url

    Args:
        url -- A valid url that returns HTML

    Return:
        A list of strings for each magent uri found on the page
    """
    rs = requests.get(url)
    return magnet_pattern.findall(rs.text)
