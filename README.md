vmailmgr.py
==========
`vmailmgr.py` is a python script which allows user to add manually chosen or
randomly generated email addresses to `/etc/postfix/virtual`.
`vmailmgr.py` uses `/etc/postfix/vmailmgrpy` as configuration file per default.
A user may only manage his own email addresses and has no access to other users
email.

Usage
-----

    $ sudo vmailmgr.py -h
    usage: vmailmgr.py [-h] {add,remove,list,info} ...

    subcommands:
      {add,remove,list,info}
        add                 Add email address(es).
        remove              Remove email address(es).
        list                List email addresses.
        info                Show the path to the configuration file and lists
                            the allowed domain names.
___
You may use `%domain.tld` to generate random email address(es).

    $ sudo vmailmgr.py add "%@obfuscated.example.com"
___
If you want to use `vmailmgr.py` with multiple configuration files, write
wrapper scripts and set `VMAILMGRPY_CONFIG` accordingly.

Debugging
---------
You may set the env variable `VMAILMGRPY_DEBUG` to anything and `vmailmgr.py` will
not execute the `postmap` and `daemon_reload` commands. See the `configuration`
section for further information.

Installation
------------

Start by downloading `vmailmgr.py` and linking it to `/usr/local/bin/vmailmgr.py`
```
cd /whatever/directory # must be readable by other users
git clone 'https://github.com/afics/vmailmgrpy.git' vmailmgrpy
ln -s /path/to/vmailmgr.py /usr/local/bin/vmailmgr.py
```

Choose a suitable configuration file from `examples/`, copy it to
`/etc/postfix/vmailmgrpy` and change it so it fits your needs.
Look at the `configuration` section for further information.
___
`vmailmgr.py` is intended to be run by sudo, so the following line must be added
to `/etc/sudoers`

    Cmnd_Alias VMAILMGRPY = /usr/local/bin/vmailmgr.py
___
You may choose between whitelisting certain users which you can do by adding the
following to `/etc/sudoers`

    <user> ALL = NOPASSWD: VMAILMGRPY

and whitelisting a group and adding users to it, which is done like
described below:
```
echo '%vmailmgrpy  ALL = NOPASSWD: VMAILMGRPY' >> /etc/sudoers
addgroup vmailmgrpy
usermod -a -G vmailmgrpy $USERNAME
```

Configuration
-------------
`/etc/postfix/vmailmgrpy`

    # inline comments are not allowed.
    # all unnecessary or unkown lines are will be discarded
    
    # You will encounter many 
    #  WARNING: Ignoring invalid configuration line.
    # messages if you copy this to your configuration file.
    # This is nothing to worry about, but be sure to check the file
    # afterwards.
    
    # the following line begins a configuration section
    # :config

    # backup = no
    #   -> if set to `yes`, `/etc/postfix/vmailmgrpy` will be backuped to
    #      `/etc/postfix/vmailmgrpy-%Y%m%d-%H%M%S` on each change.
    #      default: no

    # postmap = /usr/sbin/postmap %s
    #   -> the specified command is executed after the new configuration file
    #      was generated and saved. %s will be replaced with the path to the
    #      config file.
    #      default: none, must be set manually

    # daemon_reload = /usr/bin/systemctl reload postfix
    #   -> the specified command is executed after the postmap command
    #      was run.
    #      default: none, must be set manually

    # the following line begins a domain section
    # :domains
    
    # the basic structure of a domain entry is:
    #   subdomain.domain.tld [flags]
    # recognized flags are:
    #   * [r] -> allow random generation of addresses for this domain
    #   * [m] -> allow manual choice of addresses for this domain
    # unkown flags will be ignored
    
    # example domains
    # alias.example.com [m]
    # obfuscated.example.com [r]
    # whatever.example.com [rm]

    # the following line begins a vmail section, do not change anything
    # after this line. This line may or may not exist on the first
    # execution.
    # :vmail

`/etc/postfix/main.cf`

    [...]
    virtual_alias_maps = hash:/etc/postfix/vmailmgrpy [...]
    [...]
