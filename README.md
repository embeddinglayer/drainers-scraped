# Drainer Malware Samples

This repository contains a variety of private source code samples for various crypto drainers along with the yara rules to detect them. These file samples where found with the [Synthient Threat Intel Platform](https://synthient.com) and have been uploaded here for other researchers to analyze.
> [!NOTE]
> Password for all samples is `infected`


> [!CAUTION]
> Do not run these samples on your host machine. They are malicious and have not been vetted for backdoors. This is purely for other researchers to analyze and understand the code.


## Yara Rules

| Sample Name | Yara Rule |
| ----------- | --------- |
| [Inferno Drainer](/samples/Inferno_Drainer.zip) | InfernoDrainerJS.yar |
| [Ethane Drainer](/samples/Ethane_Drainer.zip) |  EthaneDrainerJS.yar  |
| [UNIQUE Drainer](/samples/DRAINER.zip) |  UniqueDrainerPage.yar   |
| [Solana Phantom Drainer](/samples/Solana_Phantom_Drainer.zip) | PhantomDrainerPage.yar  |

> [!NOTE]
> Scripts ending in Page, match the drainer landing page. Scripts ending in JS, match the drainer javascript.

## Detection Script

Included is a scanner for detecting the various samples. It uses the yara rules to scan and detect a match.

```bash
pip3 install -r requirements.txt
```

```bash
python3 main.py --url https://example.com
```

Example Output:
```
Detected InfernoDrainerJS
```