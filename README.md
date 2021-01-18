# CFML Admin Scan

## Setup

From the project root, initialize a Python virtual environment:
```
python3 -m venv env
```

Activate and install requirements:
```
. env/bin/activate
pip install requests beautifulsoup4 pytest
```

## Usage
The program reads a JSON file containing targets to scan. It logs information found while scanning. Apparent instances of the Lucee and Adobe ColdFusion administrator interfaces are logged as warnings.

```
./scan.py targets.json
```

## Targets

The JSON file is an array of target definitions of the following types:

### Hostname

The program will expand one hostname or multiple hostnames to check for administrator interfaces at both protocol schemes and from both CFML engine vendors. Consider the following chunk of JSON:
```
[
    {
        "hostname": [
            "domain.tld",
            "app.domain.tld"
        ]
    }
]
```
Those two hostnames will be expanded to cause the following scanned URLs:
* http://domain.tld/lucee/admin/server.cfm
* https://domain.tld/lucee/admin/server.cfm
* http://domain.tld/CFIDE/administrator/index.cfm
* https://domain.tld/CFIDE/administrator/index.cfm
* http://app.domain.tld/lucee/admin/server.cfm
* https://app.domain.tld/lucee/admin/server.cfm
* http://app.domain.tld/CFIDE/administrator/index.cfm
* https://app.domain.tld/CFIDE/administrator/index.cfm

### IP Address

One or more IP addresses can be provided as a target definition:
```
[
    {
        "ip": "1.2.3.4"
    }
]
```

For this target definition, https expansion will not be performed. These are the resulting URLs to be scanned:
* http://1.2.3.4/lucee/admin/server.cfm
* http://1.2.3.4/CFIDE/administrator/index.cfm

If interest exists, this target definition could be enhanced to scan a given CIDR expression.

### Base URL

This target definition allows one or more base URLs to be used with CFML engine vendor expansion:
```
[
    {
        "baseurl": [
            "http://app01.domain.tld:8080",
            "http://app01.domain.tld:8081"
        ]
    }
]
```

This target definition will expand to the following URLs:
* http://app01.domain.tld:8080/lucee/admin/server.cfm
* http://app01.domain.tld:8080/CFIDE/administrator/index.cfm
* http://app01.domain.tld:8081/lucee/admin/server.cfm
* http://app01.domain.tld:8081/CFIDE/administrator/index.cfm

### URL

The URL target definition explicitly defines a location to scan; no expansion will be performed. This allows specifying a non-standard location to evaluate:
```
[
    {
        "url": [
            "https://admin.domain.tld:8889/admin/cfml/"
        ]
    }
]
```
The program will scan only the URL provided, and display a warning if HTTP 200 OK is returned. To help identify false positives, the title of the HTML page is logged. A project enhancement might be to accept strings to seek in the content.

### Skipping

It is possible to skip target definitions by adding the skip property. For example:
```
[
    {
        "hostname": "domain.tld",
        "skip": true
    }
]
```

### Documenting

Since JSON doesn't allow comments without hackery, it can be difficult to include in-line documentation. The description property is suggested for this purpose:
```
[
    {
        "description": "This is the new server to be validated",
        "hostname": "new.domain.tld"
    }
]
```


## Options

If scanning for both CFML engine vendor administration interfaces is unnecessary, use the vendor command line argument argument to specify lucee or adobe:
```
./scan.py --vendor lucee targets.json
```
This will reduce the number of URLs scanned for target definitions that perform expansion.

The loglevel may be adjusted to see more detail about which URLs were actually scanned:
```
./scan.py --loglevel INFO targets.json
```


## TODO

A better reporting mechanism needs to be designed to express the result of scanning.


## License

This project is available under the MIT License. See LICENSE.