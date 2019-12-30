# PhishingKit-Yara-Search
*Yara scan Phishing Kit's Zip archive(s)*

**PhishingKit-Yara-Search** is a tool created to sort/classify grabbed phishing kits zip files (like with [StalkPhish](https://github.com/t4d/StalkPhish/)). This tool uses Yara rules to search into _not deflated_ zip files. It uses directories and files names contained into zip file raw format to classify the phishing kit with existing Yara rule.

## Features
- Scan zip files directory with several Yara rules
- Scan one file with several Yara rules
- Scan one file with one Yara rule

## Requirements
* Python 3
* yara-python
* a set of YARA rules (see: [PhishingKit-Yara-Rules](https://github.com/t4d/PhishingKit-Yara-Rules))

## Install
Install the requirements
~~~
pip3 install -r requirements.txt
~~~

## Usage
You can find a set of YARA rules dedicated to Phishing Kits zip files in the tests/rules/ directory.

## Help
~~~
$ ./PhishingKit-Yara-Search.py -h

    ____  __ __  __  __                      _____                      __  
   / __ \/ // /  \ \/ /___ __________ _     / ___/___  ____ ___________/ /_ 
  / /_/ / //_/____\  / __ `/ ___/ __ `/_____\__ \/ _ \/ __ `/ ___/ ___/ __ \
 / ____/ /\ \_____/ / /_/ / /  / /_/ /_____/__/ /  __/ /_/ / /  / /__/ / / /
/_/   /_/  \_\   /_/\__,_/_/   \__,_/     /____/\___/\__,_/_/   \___/_/ /_/ 

-= PhishingKit Yara Search - Classify phishing kits zip files with Yara rules - v0.2.0 =-

usage: PhishingKit-Yara-Search.py [-h] [-c CONFIGURATION] [-f FILE] [-r RULE]
                                  [-D DIRECTORY] [-v]

Phishing kits Zip files Yara checker

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIGURATION, --configuration CONFIGURATION
                        Configuration file to use
  -f FILE, --file FILE  File to check
  -r RULE, --rule RULE  Use specific Yara rule
  -D DIRECTORY, --directory DIRECTORY
                        Recursive search into directory
  -v, --verbose         Verbose

~~~

## Configuration file
I invite you to read the conf/example.conf file for precise tuning configuration.
Configurable parameters are:
- yara_rules_dir: directory where your Yara rules (.yar files) are stored
- yara_compiled: directory where your Yara _compiled_ rules are stored (default: /tmp/yara_rules_compiled)
- archivesDir_to_analyse: the default directory to scan

## Yara rule example
This rule detect PayPal Phishing kit, named H3ATSTR0K3, testing for some specific files and directory presence:
```yara
rule PK_PayPal_H3ATSTR0K3 : PayPal
{
    meta:
        description = "Phishing Kit impersonating PayPal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-11-28"
        comment = "Phishing Kit - PayPal - H3ATSTR0K3"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "prevents"
        // specific file found in PhishingKit
        $spec_file = "mine.php" nocase
        $spec_file2 = "bcce592108d8ec029aa75f951662de2e.jpeg"
        $spec_file3 = "captured.txt"
        $spec_file4 = "H3ATSTR0K3.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4 and
        // check for directory
        $spec_dir
}
```

## Usage with configuration file
~~~
$ ./PhishingKit-Yara-Search.py -c conf/example.conf   

    ____  __ __  __  __                      _____                      __
   / __ \/ // /  \ \/ /___ __________ _     / ___/___  ____ ___________/ /_
  / /_/ / //_/____\  / __ `/ ___/ __ `/_____\__ \/ _ \/ __ `/ ___/ ___/ __ \
 / ____/ /\ \_____/ / /_/ / /  / /_/ /_____/__/ /  __/ /_/ / /  / /__/ / / /
/_/   /_/  \_\   /_/\__,_/_/   \__,_/     /____/\___/\__,_/_/   \___/_/ /_/

-= PhishingKit Yara Search - Classify phishing kits zip files with Yara rules - v0.2.0 =-    

        file: http__vtennis.vn_forumrunner_PPL-ID.zip
                --> This rule(s) matched: [[PK_PayPal_H3ATSTR0K3]]
        file: http__lazydays.in_cgi_chase.zip
        		--> This rule(s) matched: [[PK_Chase_Xbalti]]
        file: https__35.176.252.80_ourtimes_Ourtime.zip
        		--> This rule(s) matched: [[PK_Ourtime_mmxq]]

~~~

## Usage with one rule on one file
~~~
$ ./PhishingKit-Yara-Search.py -r rules/PK_PayPal_H3ATSTR0K3.yar -f ./http__vtennis.vnforumrunner_PPL-ID.zip

   ____  __ __  __  __                      _____                      __
  / __ \/ // /  \ \/ /___ __________ _     / ___/___  ____ ___________/ /_
 / /_/ / //_/____\  / __ `/ ___/ __ `/_____\__ \/ _ \/ __ `/ ___/ ___/ __ \
/ ____/ /\ \_____/ / /_/ / /  / /_/ /_____/__/ /  __/ /_/ / /  / /__/ / / /
_/   /_/  \_\   /_/\__,_/_/   \__,_/     /____/\___/\__,_/_/   \___/_/ /_/

= PhishingKit Yara Search - Classify phishing kits zip files with Yara rules - v0.2.0 =-                                                                  

       file: ./http__vtennis.vn_forumrunner_PPL-ID.zip                                                                        
               --> This rule(s) matched: [[PK_PayPal_H3ATSTR0K3]]

~~~

## Usage with one rule on a directory containing several zip files
~~~
$ ./PhishingKit-Yara-Search.py -r rules/PK_PayPal_H3ATSTR0K3.yar -D ./dl/

    ____  __ __  __  __                      _____                      __
   / __ \/ // /  \ \/ /___ __________ _     / ___/___  ____ ___________/ /_
  / /_/ / //_/____\  / __ `/ ___/ __ `/_____\__ \/ _ \/ __ `/ ___/ ___/ __ \
 / ____/ /\ \_____/ / /_/ / /  / /_/ /_____/__/ /  __/ /_/ / /  / /__/ / / /
/_/   /_/  \_\   /_/\__,_/_/   \__,_/     /____/\___/\__,_/_/   \___/_/ /_/

-= PhishingKit Yara Search - Classify phishing kits zip files with Yara rules - v0.2.0 =-                                                                  

        file: http__vtennis.vn_forumrunner_PPL-ID.zip
                --> This rule(s) matched: [[PK_PayPal_H3ATSTR0K3]]
        file: https__investing.co.id_wp-content_upgrade_wp-file-manager-n0k7CF_wp-file-manager_languages_Secure-Mail.zip
                --> This rule(s) matched: [[PK_PayPal_H3ATSTR0K3]]
        file: http__compte-login.com_PayPalfinal.zip
                --> This rule(s) matched: [[PK_PayPal_H3ATSTR0K3]]
        file: http__compte-login.com__PayPal.zip
                --> This rule(s) matched: [[PK_PayPal_H3ATSTR0K3]]

~~~