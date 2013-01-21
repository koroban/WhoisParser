Novutec WhoisParser
===================

Lookup domain names, IP addresses and AS numbers by WHOIS.

Automatically follows the WHOIS registry referral chains until it finds the
correct WHOIS for the most complete WHOIS data. Exceptionally robust WHOIS parser
that parses a variety of free form WHOIS data into well-structured data that your
application may read. Also returns an indication of whether a domain is available.

Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
Licensed under the Apache License, Version 2.0 (the "License").

Installation
------------

Installing from source: `git clone git://github.com/novutec/WhoisParser.git` or [download the latest release](https://github.com/novutec/WhoisParser/zipball/master)

See Novutec DomainParser (http://github.com/novutec/DomainParser) or [download the latest release](https://github.com/novutec/DomainParser/zipball/master) and install it as well.

Move the source code to your preferred project folder.

Usage
-----

* Include Parser.php
```
require_once 'DomainParser/Parser.php';
require_once 'WhoisParser/Parser.php';
```

* Create Parser() object
```
$Parser = new Novutec\WhoisParser\Parser();
```

* Call lookup() method
```
$result = $Parser->lookup($domain);
$result = $Parser->lookup($ipv4);
$result = $Parser->lookup($ipv6);
$result = $Parser->lookup($asn);
```

* Access WHOIS record, the object oriented way.
```
echo $Result->created; // get create date of domain name
print_r($Result->rawdata); // get raw output as array
```

* You may choose 5 different return types. the types are array, object, json, serialize and
xml. By default it is object. If you want to change that call the format method before calling
the parse method or provide to the constructer. If you are not using object and an
error occurs, then exceptions will not be trapped within the response and thrown directy.
```
$Parser->setFormat('json');
$Parser = new Novutec\WhoisParser\Parser('json');
```

* You may set your own date format if you like. Please check http://php.net/strftime for further
details
```
$Parser->setDateFormat('%d.%m.%Y %H:%M:%S');
```

* If you have special WHOIS server or login credentials for a registrar WHOIS you may use
the method setSepcialWhois(). Please note that if you have a special WHOIS and the WHOIS output
looks different you need your own template.
```
$Parser->setSepcialWhois('it' => array('server' => 'whois.nic.it', 'port' => 43,
'format' => '-u username -w passsword %domain%', 'template' => 'it-your-own-template'));
```

ToDos
-----
* Caching of data for better performance and to reduce requests
* Optional logging of raw data and/or parsed data for audit proposes 

Known bugs to be fixed in further versions
------------------------------------------
* [Template] gTLD cps-datensysteme - need caching for testing, because after 5 requests you get blocked
* [Template] .CZ - found a strange behavior by matching the contact handles with google.cz
* [Template] .BJ - recursive lookup for handles

Tested with following RIRs and TLDs
----------------------------------
RIRs
```
[x] Afrinic
[x] Apnic
[x] Arin
[x] Krnic
[x] Lacnic
[x] Ripe
```

ccTLDs (http://data.iana.org/TLD/tlds-alpha-by-domain.txt)
```
[x] AC
[ ] AD
[x] AE
[x] AERO
[x] AF
[x] AG
[x] AI
[ ] AL
[x] AM
[ ] AN
[ ] AO
[ ] AQ
[ ] AR - webbased
[ ] ARPA
[x] AS
[x] ASIA
[x] AT
[x] AU
[ ] AW
[x] AX
[ ] AZ - webbased
[ ] BA - webbased
[ ] BB - webbased with captcha
[ ] BD
[x] BE
[ ] BF
[x] BG
[ ] BH
[x] BI
[x] BIZ
[ ] BJ - need recursive calls for handles
[ ] BM - webbased
[ ] BN
[x] BO
[x] BR
[ ] BS - webbased
[ ] BT
[ ] BV - no domains but it is NORID
[ ] BW
[x] BY
[x] BZ
[x] CA
[x] CAT
[x] CC
[x] CD
[ ] CF
[ ] CG - webbased with captcha
[x] CH
[ ] CI - need recursive calls for handles
[x] CK
[ ] CL - possible
[x] CM
[x] CN
[x] CO
[x] COM
[ ] COOP - to few domain names
[ ] CR
[ ] CU
[ ] CV
[ ] CW
[x] CX
[ ] CY
[x] CZ
[x] DE
[x] DE Registrar WHOIS
[ ] DJ
[x] DK
[x] DM
[ ] DO
[ ] DZ - whois server on port 43 is broken, http get whois possible
[x] EC
[x] EDU
[x] EE
[ ] EG
[ ] ER
[x] ES
[ ] ET
[x] EU
[x] FI
[ ] FJ (whois.usp.ac.fj)
[ ] FK
[x] FM
[x] FO
[x] FR
[ ] GA
[ ] GB
[x] GD
[ ] GE
[ ] GF
[x] GG
[ ] GH
[x] GI
[X] GL
[ ] GM
[ ] GN
[ ] GOV - to few domain names
[ ] GP
[ ] GQ
[ ] GR
[x] GS
[ ] GT  - webbased
[ ] GU
[ ] GW
[x] GY
[x] HK
[ ] HM (whois.registry.hm)
[x] HN
[ ] HR - possible
[x] HT
[ ] HU - webbased with captcha
[ ] ID (whois.idnic.net.id)
[ ] IE - possible
[X] IL
[x] IM
[x] IN
[x] INFO
[x] INT
[x] IO
[x] IQ
[X] IR
[X] IS
[x] IT
[x] IT Registrar WHOIS
[x] JE
[ ] JM
[ ] JO
[x] JOBS
[x] JP
[x] KE
[x] KG
[ ] KH
[x] KI
[ ] KM
[ ] KN
[ ] KP
[x] KR
[ ] KW
[ ] KY
[x] KZ
[x] LA
[ ] LB
[x] LC
[x] LI
[ ] LK (whois.nic.lk)
[ ] LR
[ ] LS
[x] LT
[x] LU
[x] LV
[ ] LY - possible
[ ] MA - possible
[ ] MC
[ ] MD - possible
[x] ME
[x] MG
[ ] MH
[ ] MIL - useless
[ ] MK
[ ] ML
[ ] MM
[x] MN
[ ] MO
[x] MOBI
[ ] MP - whois on port 43 broken
[ ] MQ
[ ] MR
[x] MS
[ ] MT (whois.nic.org.mt) mit captcha
[x] MU
[x] MUSEUM
[ ] MV
[ ] MW
[x] MX
[ ] MY - possible
[ ] MZ
[x] NA
[ ] NAME - possible
[ ] NC - possible
[ ] NE
[x] NET
[x] NF
[x] NG
[ ] NI
[x] NL
[ ] NO - possible - need recursive lookup for nameserver
[ ] NP
[ ] NR
[ ] NU - possible
[x] NZ
[x] OM
[x] ORG
[ ] PA
[x] PE
[ ] PF
[ ] PG
[ ] PH
[ ] PK - webbased
[x] PL
[x] PM
[ ] PN
[ ] PR - whois on port 43 broken
[x] PRO
[ ] PS
[ ] PT - possible
[x] PW
[ ] PY
[x] QA
[x] RE
[ ] RO - possible
[x] RS
[ ] RU - possible
[ ] RW
[ ] SA - possible
[x] SB
[x] SC
[ ] SD
[ ] SE - possible
[ ] SG - possible
[x] SH
[ ] SI - possible
[ ] SJ - no domains but it is NORID
[ ] SK - possible
[ ] SL
[ ] SM - possible
[ ] SN - whois on port 43 broken
[x] SO
[ ] SR
[ ] ST - possible
[ ] SU - possible -> RU
[ ] SV
[x] SX
[ ] SY
[ ] SZ
[x] TC 
[ ] TD 
[x] TEL
[x] TF
[ ] TG
[ ] TH - possible
[ ] TJ
[ ] TK - possible
[x] TL
[x] TM
[ ] TN - whois server on port 43 broken
[ ] TO - useless
[ ] TP
[x] TR
[x] TRAVEL
[ ] TT - webbased 
[x] TV
[x] TW
[ ] TZ
[ ] UA - possible
[ ] UG - possible
[x] UK
[x] US
[ ] UY - possible
[ ] UZ - possible
[ ] VA
[x] VC
[ ] VE - whois server on port 43 broken
[x] VG
[ ] VI
[ ] VN
[ ] VU
[x] WF
[x] WS
[ ] XN--0ZWM56D
[ ] XN--11B5BS3A9AJ6G
[ ] XN--3E0B707E - possible .kr
[x] XN--45BRJ9C - .in
[ ] XN--80AKHBYKNJ4F
[ ] XN--80AO21A - possible .kz
[ ] XN--90A3AC - possible .rs
[ ] XN--9T4B11YI5A
[ ] XN--CLCHC0EA0B2G2A9GCD - possible .sg
[ ] XN--DEBA0AD
[x] XN--FIQS8S - .cn
[x] XN--FIQZ9S - .cn
[x] XN--FPCRJ9C3D - .in
[ ] XN--FZC2C9E2C
[ ] XN--G6W251D
[x] XN--GECRJ9C - .in
[x] XN--H2BRJ9C - .in
[ ] XN--HGBK6AJ7F53BBA
[ ] XN--HLCJ6AYA9ESC7A
[x] XN--J6W193G - .hk
[ ] XN--JXALPDLP
[ ] XN--KGBECHTV
[x] XN--KPRW13D - .tw
[x] XN--KPRY57D - .tw
[ ] XN--LGBBAT1AD8J - possible .dz
[ ] XN--MGBAAM7A8H - possible .ae
[ ] XN--MGBAYH7GPA
[x] XN--MGBBH1A71E - .in
[ ] XN--MGBC0A9AZCG - don't know but it is .ma
[ ] XN--MGBERP4A5D4AR - possible .sa
[ ] XN--O3CW4H - possible .th
[ ] XN--OGBPF8FL
[ ] XN--P1AI - possible .ru
[ ] XN--PGBS0DH
[x] XN--S9BRJ9C - .in
[ ] XN--WGBH1C
[ ] XN--WGBL6A - possible .qa
[ ] XN--XKC2AL3HYE2A
[x] XN--XKC2DL3A5EE0H - .in
[ ] XN--YFRO4I67O - possible sgnic
[ ] XN--YGBI2AMMX - possible .ps
[ ] XN--ZCKZAH
[x] XXX
[ ] YE
[x] YT
[ ] ZA - webbased whois.co.za
[ ] ZM
[ ] ZW
```

Special TLDs
```
[x] CentralNic (https://www.centralnic.com/names/domains)
[x] CO.NL
[x] CO.NO
[x] COM.CC
[x] ORG.CC
[x] EDU.CC
[x] NET.CC
```

gTLDs and thin registries sort by IANA ID (http://www.iana.org/assignments/registrar-ids/registrar-ids.xml)
```
[x] 2 (Network Solutions, LLC)
[x] 13 (Melbourne IT, Ltd)
[x] 15 (CORE Internet Council of Registrars)
[x] 48 (eNom, Inc.)
[x] 49 (GMO Internet, Inc. d/b/a Onamae.com)
[x] 69 (Tucows Domains Inc.)
[x] 81 (Gandi SAS)
[x] 83 (1&1 Internet AG)
[ ] 106 (Ascio Technologies, Inc. - Denmark)
[x] 120 (Xin Net Technology Corporation)
[x] 226 (Deutsche Telekom AG)
[x] 269 (Key-Systems GmbH)
[x] 141 (Cronon AG)
[x] 151 (PSI-USA, Inc. dba Domain Robot)
[x] 648 (Webagentur.at Internet Services GmbH d/b/a domainname.at)
[x] 828 (Hetzner Online AG)
[x] 1239 (CPS-Datensysteme GmbH)
[x] 1257 (Variomedia AG dba puredomain.com)
[x] 1328 (RegistryGate GmbH)
[x] 1387 (1API GmbH)
[x] 1408 (united-domains AG)
[x] 1420 (InterNetworX Ltd. & Co. KG)
[ ] Antagus.de
[ ] BasicFusion.com
[ ] BizCn.com
[ ] Corporate Domains
[ ] DirectNic
[ ] DomainPeople
[ ] Domainsite.com
[ ] DotRegistrar
[ ] Dotster
[ ] Dreamhost
[ ] Dynadot
[ ] EPAG
[ ] GoDaddy
[ ] HTTP.net
[ ] Joker.com
[ ] Fabulous.com
[ ] FastDomain.com
[ ] MarkMonitor
[ ] Name.com
[ ] NameKing.com
[ ] Names4ever
[ ] Namesdirect
[ ] Namesecure
[ ] Nicline
[ ] OnlineNic
[ ] OVH
[ ] Register.com
[ ] Register.it
[ ] ResellerClub.com
[ ] Srsplus
[ ] Webnic
[ ] WildWestDomains
[x] Novutec Inc.
```

3rd Party Libraries
-------------------
We are using our own DomainParser:
* Novutec: http://github.com/novutec/DomainParser (Version 1.1.5 and above)

ChangeLog
---------
See ChangeLog at https://github.com/novutec/WhoisParser/wiki/ChangeLog

Issues
------
Please report any issues via https://github.com/novutec/WhoisParser/issues

LICENSE and COPYRIGHT
-----------------------
Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.