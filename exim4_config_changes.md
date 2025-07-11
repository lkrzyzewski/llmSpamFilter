# Changes to exim4 config file

...

daemon_smtp_ports = 25 : 465 : 587 : 10025 : 10029

...

begin routers

...

route_to_phishing:
    driver = manualroute
    verify_recipient = false
    verify_sender = true
    # Condition: Do not process mail already processed by Amavis (10025)
    # or through this own filter (incoming to 10029)
    condition = "${if eq {$interface_port}{10025} {0}{1}}"
    condition = "${if eq {$interface_port}{10029} {0}{1}}"      
    condition = ${if eq{$sender_address}{virus-quarantine@point-group.pl}{no}{yes}}
    condition = ${if eq{$sender_address}{a.borzecki@pmpg.pl}{no}{yes}}
    transport = phishing
    route_list = "* localhost byname"
    # Important: This causes Exim to retry sending to this transport 
    # instead of trying other routers in the event of a temporary filter error.
    self = send
    # We do not typically verify the recipient for content filters.
    # verify_recipient = false
    # Stop processing routers if this one matches and the transport succeeds. 
    # The mail will be re-injected through the Python filter.
    no_more

amavislocal:
        driver = manualroute
        verify_recipient = false
        verify_sender = true
        condition = "${if eq {$interface_port}{10025} {0}{1}}" # Important
        condition = "${if eq {$interface_port}{10029} {1}{0}}" # Important
        condition = ${lookup ldap{LDAP_QUERY?locMailActive?sub?\
          (&\
            (locMailActive=TRUE)\
            (|\
              (mailRoutingAddress=${quote_ldap:$sender_address})\
              (mailLocalAddress=${quote_ldap:$sender_address})\
            )\
          )} {true} {false} }
        # if scanning incoming mails, uncomment the following line and
        # change local_domains accordingly
#        domains = +local_domains
        condition = ${if eq{$sender_address}{virus-quarantine@point-group.pl}{no}{yes}}
        condition = ${if eq{$sender_address}{a.borzecki@pmpg.pl}{no}{yes}}
        transport = ${lookup ldap{LDAP_QUERY?locAddDisclaimer?sub?\
          (&\
            (locMailActive=TRUE)\
            (|\
              (mailRoutingAddress=${quote_ldap:$sender_address})\
              (mailLocalAddress=${quote_ldap:$sender_address})\
            )\
          )} {amavisdiscl} {amavislocal} }
#	  )} {amavislocal} {amavislocal} }
        route_list = "* localhost byname"
        self = send
        
amavis:
        driver = manualroute
        verify_recipient = false
#        verify_sender = false
        condition = "${if eq {$interface_port}{10025} {0}{1}}" # Important
        condition = "${if eq {$interface_port}{10029} {1}{0}}" # Important
        condition = ${if eq{$sender_address}{virus-quarantine@point-group.pl}{no}{yes}}
        condition = ${if eq{$sender_address}{a.borzecki@pmpg.pl}{no}{yes}}
        # if scanning incoming mails, uncomment the following line and
        # change local_domains accordingly
#       domains = +local_domains
        transport = amavis
        route_list = "* localhost byname"
        self = send
        
        
...

begin transports

...

phishing:
        driver = smtp
        port = 10030
        allow_localhost
        command_timeout = 30s
        connect_timeout = 30s
        data_timeout = 60s
