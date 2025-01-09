"""
Author: github.com/@embeddinglayer
Date: 01/09/2025
Crypto Drainer Detection Tool
    Detections for the following Families:
        - EtherDrainer
        - UniqueDrainer
        - InfernoDrainer
        - PhantomDrainer

    Usage:
        python3 main.py --url https://example.com
"""

import argparse
import os
import re
from typing import Any, Dict

# Bypass tls fingerprinting for CF
import curl_cffi.requests as requests

import yara

JAVASCRIPT_REGEX = re.compile(r'<script.*?src="(.*?\.js)".*?>')


def main() -> None:
    """Entry point for the script."""
    args = argparse.ArgumentParser()
    args.add_argument("--url", help="URL to scan", required=True)
    args = args.parse_args()

    rules = os.listdir("yara")

    detections: Dict[str, Any] = {}
    for rule in rules:
        detections[rule.rsplit(".", 1)[0]] = yara.compile(f"yara/{rule}")

    response = requests.get(args.url, verify=False)
    scripts = re.findall(
        JAVASCRIPT_REGEX,
        response.text,
    )
    for script in scripts:
        script = script.replace("./", "")
        script_response = requests.get(f"{args.url}/{script}", verify=False)
        for rule, yar in detections.items():
            if rule.endswith("JS"):
                matches = yar.match(data=script_response.content)
                if matches:
                    print("Detected", rule)

    for rule, yar in detections.items():
        if rule.endswith("Page"):
            if yar.match(data=response.text):
                print("Detected", rule)


if __name__ == "__main__":
    main()
