#!/usr/bin/python
"""Poor Opssec
    A collection of techniques and methods to capture not terribly intelligent / hidden
    entities who do not practice proper Operational Security or are using these techniques
    to cause the blue team to spend time spinning their tires in the mud.  Best case, this
    allows one to transition earlier in the killchain.  For instance, instead of black-holing
    the afflicted domains, point them to a deceptive honeypot and infrastructure meant
    for deception and offensive security time-wasting.
    """
import entropy
import logging
import re
from Levenshtein import ratio
from time import time

import certstream
import requests
import tqdm
from tld import get_tld

from indicators import phrases, prefixes

'''setup logging for syslog and other eventual event communication services.'''
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)
HANDLER = logging.FileHandler('./NeedSpecialAttention.log')
HANDLER.setLevel(logging.INFO)
FORMATTER = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(HANDLER)
STATUSCLI = tqdm.tqdm(desc='certificate_update', unit='cert')


def live_status_check(phishy):
    """Is the evil domain alive or some other state?
        input:
        phishy - the domain (str)

        returns - status_code (int) The HTTP status code.  -1 means timeout or unable to connect.
        """
    try:
        _status_response = requests.get('http://' + phishy, timeout=2.2)
        _status_code = _status_response.status_code
    except Exception as exc:
        _status_code = -1
    finally:
        return _status_code


def tweet_finding(tweet_content):
    """Tweet the finding
          input:
          tweet_content - the content to put into the tweet to public announce or DM (str)

          returns - N/A in public version
          """

    ##Nothing here in the public version

    return 1



def stix_export(stix_content):
    """Publish to a STIX-enabled service for threat and vuln mgt.
          input:
          stix_content - the base content used to create the STIX message / event

          returns - N/A in public version
          """

    ##Nothing here in the public version

    return 1


def alleged_domain(phishy):
    """How sketchy is the domain in question?  Performs statistical, symantic, and other reasoning techniques to
        separate the wheat from the chaff
        input:
        phishy - the domain (str)

        returns - score (int or float depending on the quant. techniques
        """

    score = 0
    for _tld in prefixes:
        if phishy.endswith(_tld):
            score += 20

    if phishy.startswith('*.'):
        phishy = phishy[2:]

    # https://arstechnica.com/information-technology/2017/06/phishing-attacks-target-mobile-browsers-with-dash-padded-urls/
    try:
        res = get_tld(phishy, as_object=True, fail_silently=True, fix_protocol=True)
        phishy = '.'.join([res.subdomain, res.domain])
    except Exception as exc:
        pass

    words_in_domain = re.split("\W+", phishy)

    # How fun are wildcards?  Not fun with language parsers
    if phishy.startswith('*.'):
        phishy = phishy[2:]
        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

    # Testing keywords
    for word, val in phrases.iteritems():
        if word in phishy:
            score += phrases[word]

    # Too random?
    score += int(round(entropy.shannon_entropy(phishy) * 50.2))

    # How likely is this like others?
    for key in [k for (k, s) in phrases.items() if s >= 70]:
        # Massaging dataset massaging with normalization
        for word in [w for w in words_in_domain if w not in ['cloud', 'mail', 'email']]:
            if ratio(str(word), str(key)) == 1:
                score += 70

    '''Markov chain confusion Not released to the public'''
    '''K closest neighbors and cluster analysis (similar to Levenshstein ratios) not released to the public'''

    #Oh China....
    if 'xn--' not in phishy and phishy.count('-') >= 4:
        score += phishy.count('-') * 3

    # Humans rarely, rationally pick 3+ subdomains deep
    if phishy.count('.') >= 3:
        score += phishy.count('.') * 3

    return score


def verisign_certstream(handle_symantec):
    """Handlers to consume various verisign / symantec certificate streams
          input:
          handle_symantec - a dictionary of various symantec / verisign certificate streams

          returns - N/A in public version
          """

    ##Nothing here in the public version

    return 1

def palo_alto_networks(pan_content):
    """Publish to a PAN service or appliance to enable deceptive routing.
          input:
          pan_content - the base content used to create the PAN policy

          returns - N/A in public version
          """

    ##Nothing here in the public version

    return 1


def ids_export(regex_pattern):
    """Publish to a Suricata, Bro, and / or Snort API.  Also create the written ids rules in the corresponding directory
          input:
          regex_pattern - the base regex used to construct a generic IDS pattern.  Then highly customized / tweaked
          for specific IDS engines and pattern matching algorithms.

          returns - N/A in public version
          """

    ##Nothing here in the public version

    return 1



def log_me(bad_fish, weight):
    """Takes the weight of an alleged evil domain and communicates it as appropriate
        input:
        bad_fish - the domain (str)
        weight - the quantitative evil (int or float)

        returns - success just because?!
        """

    '''Mean in a normal distribution with a width of 2, 4, and 6 standard deviations'''
    if weight >= 68:
        status = live_status_check(bad_fish)
        LOGGER.info("time={0} weight={1} bad_fish={2} http_status={3}\n".format(int(time()), weight, bad_fish, status))

    return 1

def callback(message, context):
    """Specifying the function as an entity.
        input:
        message - entity's message
        context - in case future needs dictate a calling code context

        returns - much success
        """
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        _cert_firehose = message['data']['leaf_cert']['all_domains']

        for _smelly_domain in _cert_firehose:
            score = alleged_domain(_smelly_domain.lower())
            STATUSCLI.update(1)

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                score += 10

            log_me(_smelly_domain, score)

if __name__ == "__main__":
    certstream.listen_for_events(callback)
