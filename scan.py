#!/usr/bin/env python3

import argparse
import requests
from requests.exceptions import Timeout, SSLError, RequestException, ConnectionError
import json
from json.decoder import JSONDecodeError
import logging
from bs4 import BeautifulSoup


def as_list(value):
    if isinstance(value, list):
        return value
    return [value]


def process_targets(filename, vendor):
    targets = json.load(open(filename, "r"))
    scan_queue = list()

    for target in targets:
        baseurls = list()
        if "skip" in target and target["skip"]:
            continue

        if "url" in target:
            target["url"] = as_list(target["url"])
            for url in target["url"]:
                scan_queue.append(url)
            continue

        if "baseurl" in target:
            target["baseurl"] = as_list(target["baseurl"])
            for baseurl in target["baseurl"]:
                if baseurl[-1] == "/":
                    baseurl = baseurl[:-1]
                baseurls.append(baseurl)

        if "hostname" in target:
            target["hostname"] = as_list(target["hostname"])
            for hostname in target["hostname"]:
                baseurls.append("http://" + hostname)
                baseurls.append("https://" + hostname)

        if "ip" in target:
            target["ip"] = as_list(target["ip"])
            for ip in target["ip"]:
                baseurls.append("http://" + ip)

        for baseurl in baseurls:
            if vendor == "all" or vendor == "lucee":
                scan_queue.append(baseurl + "/lucee/admin/server.cfm")
            if vendor == "all" or vendor == "adobe":
                scan_queue.append(baseurl + "/CFIDE/administrator/index.cfm")

    return scan_queue


def scan(urls):
    for url in urls:
        try:
            response = requests.get(url, timeout=(3.05, 27))
            if response.status_code >= 200 and response.status_code < 300:
                soup = BeautifulSoup(response.text, "html.parser")
                if soup.find("title"):
                    logging.warning("{0} Title: {1}".format(url, soup.title.string))
                else:
                    logging.warning("{0} {1} {2}".format(url, response.status_code, response.reason))
            else:
                logging.info("{0} {1} {2}".format(url, response.status_code, response.reason))
        except Timeout:
            logging.info(url + " Connection timeout")

        except SSLError:
            logging.info(url + " SSL setup error")

        except ConnectionError:
            logging.info(url + " Connection error")

        except RequestException as e:
            logging.info(url + str(e))

        except Exception as e:
            logging.error(url + str(e))


def main():
    parser = argparse.ArgumentParser(description="Scan for exposed CFML engine administration web interfaces")
    parser.add_argument("--loglevel", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Python logging level")
    parser.add_argument("--vendor", default="all", choices=["lucee", "adobe", "all"],
                        help="The CFML engine vendors for URL expansion")
    parser.add_argument("targets", help="The JSON file containing targets to scan")
    args = parser.parse_args()

    loglevel = getattr(logging, args.loglevel)
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=loglevel)

    logging.debug("Processing targets file " + args.targets)
    try:
        scan_queue = process_targets(args.targets, args.vendor)
    except JSONDecodeError:
        logging.error("Failure parsing JSON file " + args.targets)
        exit(1)

    logging.info("Scanning {0} URLs".format(len(scan_queue)))
    scan(scan_queue)


if __name__ == "__main__":
    main()
