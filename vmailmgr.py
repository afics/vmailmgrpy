#!/usr/bin/python3
# 2013 (c) by Armin Fisslthaler <armin@fisslthaler.net>
# This script is intended to be used as a sudo wrapper to manage to manage a 
# virtual address file as used by postfix.

import argparse
import sys
import os
import re
import string
import random
from datetime import datetime
from subprocess import call
from smtplib import SMTP

# does some vmailmgr specific things, do not use in other scripts
class EmailAddr():
    def __init__(self, email):
        self.email = email
        try:
            self.user, self.domain = email.split("@")
        except ValueError:
            raise ValueError("Email address '{}' is invalid. ".format(email)
                           + "Multiple at symbols are not allowed.") from None

        # % -> used to recognize random addrs in VirtualMailMgr()
        if self.user != "%" and re.match("^[a-z0-9._+-]+$", self.user) == None:
            raise ValueError("'%s' contains an invalid character!" % email)

    def __str__(self):
        return "%s@%s" % (self.user, self.domain)


class VirtualMailMgr():
    def __init__(self, db_path="/etc/postfix/vmailmgrpy", cli=True,
                 debug=False):
        self._db_path = db_path
        self._debug = debug

        if cli:
            self._cli()

    def _cli(self):
        parser = argparse.ArgumentParser()
        sp = parser.add_subparsers(title="subcommands", dest="command")
        subcmd = {
            "add": sp.add_parser(
                "add",
                formatter_class=argparse.RawTextHelpFormatter,
                help="Add email address(es).",
                description="Add email address(es).\nYou may use %@domain.tld "
                          + "to generate random email address(es)"
            ),

            "remove": sp.add_parser(
                "remove",
                help="Remove email address(es)."
            ),

            "list": sp.add_parser(
                "list",
                help="List email addresses."
            ),

            "info": sp.add_parser(
                "info",
                formatter_class=argparse.RawTextHelpFormatter,
                help="Show the path to the configuration file and lists the "
                   + "allowed domain names.",
                description="Show the path to the configuration file and lists"
                          + "\nthe allowed domain names.\n\n"
                          + "The list of the allowed domain names may look "
                          + "like this:\n"
                          + "  domain.tld [rm]\n"
                          + "where the letters in the [] represent flags.\n\n"
                          + "[r] -> Generation of random email addresses is"
                          + "permitted.\n"
                          + "[m] -> User chosen email addresses are permitted."
            ),
        }

        subcmd["add"].add_argument(
            "addrs",
            metavar="addr",
            nargs="+",
            help="Email address to add/remove. Note: the domain must be "
                + "included."
        )

        subcmd["remove"].add_argument(
            "addrs",
            metavar="addr",
            nargs="+",
            help="Email address to add/remove. Note: the domain has to be "
               + "included."
        )

        args = parser.parse_args()
        if not args.command:
            parser.error('Subcommand required!')

        try:
            os.environ['SUDO_USER']
        except KeyError:
            parser.error('This script is intended to be run by sudo!')

        self._user = os.getlogin()
        self._command = args.command

        self._load_db()

        getattr(self, args.command)(args)

    def _randomstr(self, characters=string.ascii_lowercase + string.digits,
                   length=16):
        return "".join([random.choice(characters) for n in range(length)])

    def _report(self, msg):
        s = SMTP("localhost")
        s.sendmail("vmailmgrpy@localhost", "root@localhost",
                   "Subject: vmailmgrpy failure report\n%s\n" % msg
                 + "command: %s\nuser: %s" % (self._command, self._user))

    def _reload_daemon(self):
        if self._debug:
            print("WARNING: NOT running postmap and NOT reloading"
                + "daemon, we\'re in DEBUG mode.")
        else:
            r = call(self._config["postmap"] % self._db_path, shell=True)
            if r != 0:
                self._report("postmap failed!")
                print("postmap failed, report sent to root@localhost.")
                return
            
            r = call(self._config["daemon_reload"], shell=True)
            if r != 0:
                self._report("daemon_reload failed!")
                print("daemon_reload failed, report sent to "
                    + "root@localhost.")

    def _load_db(self):
        self._db = {}
        self._addresses = []
        self._domains = {}
        self._config = {}

        stage = "unkown"

        cf = open(self._db_path, "r")
        for line in cf:
            ls = line.strip()
            if ls[:3] == "# :":
                if ls == "# :config":
                    stage = "config"
                    continue
                if ls == "# :domains":
                    stage = "domain"
                    continue
                elif ls == "# :vmail":
                    stage = "vmail"
                    continue
                else:
                    print("error: Unkown configuration section.")
                    sys.exit(2)

            if ((line[0] == "#" and (stage != "domain" and stage != "config"))
                or len(line) == 1):
                continue # ignore comments or empty lines

            if stage == "unkown":
                continue # TODO: should never happen

            elif stage == "domain":
                try:
                    domain, flags = ls[1:].strip().split(" ")
                    flags = flags.strip()[1:-1]
                except ValueError or IndexError:
                    print("WARNING: Ignoring invalid configuration line.")
                    continue
                
                self._domains[domain] = {}
                self._domains[domain]["random"] = "r" in flags
                self._domains[domain]["manual"] = "m" in flags

            elif stage == "vmail":
                addr, target = ls.split(" ")
                self._add(addr, target)

            elif stage == "config":
                try:
                    key, value = ls[1:].strip().split("=")
                except ValueError:
                    print("WARNING: Ignoring invalid configuration line.")
                    continue

                if value.strip().lower() == "yes":
                    value = True
                elif value.strip().lower() == "no":
                    value = False
                else:
                    value = value.strip()

                self._config[key.strip()] = value

        cf.close()

        if "daemon_reload" not in self._config or "postmap" not in self._config:
            print("One of the required configuration options [daemon_reload,\n"
                + "postmap] is missing, aborting.")
            sys.exit(3)

    def _save_db(self):
        if self._config.get("backup", False):
            os.rename(self._db_path,
                      "%s-%s" % (self._db_path,
                                 datetime.today().strftime('%Y%m%d-%H%M%S')))
        
        cf = open(self._db_path, "w")
        cf.write("# WARNING: This file is autogenerated, do not edit!\n")
        cf.write("\n# :config\n")
        for k, v in sorted(self._config.items()):
            if type(v) == bool:
                v = "yes" if v else "no"
            cf.write("# %s = %s\n" % (k, v))

        cf.write("\n# :domains\n")
        for domain, v in sorted(self._domains.items()):
            cf.write("# %s [%s%s]\n" % (domain,
                                        "r" if v.get("random", True) else "", 
                                        "m" if v.get("manual", False) else ""))
        
        cf.write("\n# :vmail\n")
        for user in sorted(self._db):
            cf.write("# %s\n" % user)
            for addr in sorted(self._db[user]):
                cf.write("%s %s\n" % (addr, user))
            cf.write("\n")

        cf.close()

    def _add(self, addr, user=None):
        if user == None:
            user = self._user
        try:
            self._db[user].append(str(addr))
        except KeyError:
            self._db[user] = [str(addr)]
        self._addresses.append(str(addr))

    def add(self, args):
        for addr in args.addrs:
            try:
                addr = EmailAddr(addr)
            except:
                print("'%s' will not be accepted by this script, doing" % addr
                    + " nothing...")
                continue

            if addr.domain not in self._domains:
                print("'%s' is not on the whitelist, " % addr.domain
                    + "ignoring '%s'" % addr)
                continue
            
            if str(addr) in self._addresses:
                print("%s already exists. It may be owned by " % addr
                    + "another user, ignoring...")
                continue

            if addr.user == '%': # TODO: permission check
                if not self._domains[addr.domain].get("random", True):
                    print("Random generation of email addresses for "
                        + "'%s' is not permitted." % addr.domain)
                    continue
                
                cnt = 0
                while ((str(addr) in self._addresses
                        or addr.user == "%")
                       and cnt <= 10):
                    cnt += 1
                    addr.user = self._randomstr()

                if cnt > 10 and str(addr) in self._addresses:
                    print("Could not generate a random address which "
                        + "did not already exist.\nGave up after 10 "
                        + "attempts, you may just try again.")
                elif str(addr) not in self._addresses:
                    self._add(addr)
                    print("'%s' was generated and added." % addr)
                else:
                    print("Somewhere, something went terribly wrong.")
            else:
                if not self._domains[addr.domain].get("manual", False):
                    print("Manual addition of email addresses is not "
                        + "permitted. You may try generating random "
                        + "ones.")
                else:
                    self._add(addr)
                    print("'%s' was added." % addr)

        self._save_db()
        self._reload_daemon()

    def remove(self, args):
        for addr in args.addrs:
            try:
                addr = EmailAddr(addr)
            except ValueError:
                print("'%s' will not be accepted by this script, doing" % addr
                    + " nothing...")
                continue

            try:
                self._db[self._user].remove(str(addr))
                self._addresses.remove(str(addr))
                print("%s was removed." % addr)
            except ValueError:
                print("%s does not exist, doing nothing..." % addr)

        self._save_db()
        self._reload_daemon()

    def list(self, args):
        try:
            for addr in sorted(self._db[self._user]):
                print(addr)
        except KeyError:
            pass # user does not have any email addresses yet.

    def info(self, args):
        print("Hello %s, here's the information you requested." % self._user)
        print("The virtual address db is '%s'" % self._db_path)
        print("Available domains:")
        for k, v in self._domains.items():
            print("  %s [%s%s]" % (k, "r" if v.get("random", True) else "", 
                                      "m" if v.get("manual", False) else ""))

if __name__ == "__main__":
    if "VMAILMGRPY_CONFIG" in os.environ:
        vmm = VirtualMailMgr(db_path=os.environ["VMAILMGRPY_CONFIG"],
                             debug=("VMAILMGRPY_DEBUG" in os.environ))
    else:
        vmm = VirtualMailMgr(debug=("VMAILMGRPY_DEBUG" in os.environ))

