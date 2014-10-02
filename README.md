iLoot
=====

Using this CLI tool you can download backups of devices assigned to your AppleID. Based on [iphone-dataprotection](https://code.google.com/p/iphone-dataprotection/) script, so copyrights belong to respective owners. Offset operations added and other minor bugs fixed.

**This tool is for educational purposes only. Before you start, make sure it's not illegal in your country.**

Follow us on twitter [@hackappcom](https://twitter.com/hackappcom)  and [facebook](https://www.facebook.com/groups/1480690882187595/)

Hackapp [blog](blog.hackapp.com)

Mobile Applications Scanner [hackapp.com](https://hackapp.com)

Requirements
============

```bash
pip install -r requirements.txt
```

Example
======

```bash
$ python iloot.py -h
usage: iloot [-h] [--output OUTPUT] [--item-types ITEM_TYPES [ITEM_TYPES ...]]
             apple_id password

positional arguments:
  apple_id              Apple ID
  password              Password

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output Directory
  --item-types ITEM_TYPES [ITEM_TYPES ...], -t ITEM_TYPES [ITEM_TYPES ...]
                        Only download the specified item types. Options
                        include address_book, calendar, sms, call_history,
                        voicemails, and photos. E.g., --types sms voicemail
```

By default, the tool will download everything in a backup. If you'd only like to download a specific item type (such as all SMSs), just specify the `--item-types` argument. For instance:

```bash
python iloot.py <appleID> <password> --item-types sms call_history voicemails
```

![iLoot](https://raw.githubusercontent.com/hackappcom/iloot/master/iloot.png "iloot")

