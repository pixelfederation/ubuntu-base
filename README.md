# - Ubuntu Base Container -

Ubuntu base container packaged with logstash-forwarder, supervisord and several useful scripts intended to be used with containers based off of it.

##### Version Information:
* **Container Release:** 1.0.2

---
---
### Index

* [About](#about)
* [Helper Functions](#helper-functions)
 * [cidr2mask](#cidr2mask)
 * [mask2cidr](#mask2cidr)
 * [escape_svsr_txt](#escape_svsr_txt)
* [Supervisor Config Functions](#supervisor-config-functions)
 * [config_service_keepalived](#config_service_keepalived)
 * [config_service_logrotate](#config_service_logrotate)
 * [config_service_logstash_forwarder](#config_service_logstash_forwarder)
 * [config_service_nslcd](#config_service_nslcd)
 * [config_service_redpill](#config_service_redpill)
 * [config_service_rsyslog](#config_service_rsyslog)
* [Application Config Functions](#application-config-functions)
 * [config_keepalived](#config_keepalived)

---
---

### About

#### Container Functions
All init scripts that use this image as their base source a bash script supplying useful functions to configure supervisor settings or other components used throughout the various init scripts. It can be found in `/opt/scripts/container_functions.lib.sh`.

#### Logstash-Forwarder
Logstash-forwarder is currently baked into the container. This is more a stop-gap till the logstash Mesos framework matures. In an environment where components can produce a multitude of different types of logs, sending everything to stdout/stderr can be problematic on the log-processing end.

Wherever possible logging formats and settings can be defined for both file and stdout/stderr levels. If logstash-forwarder is not to be used, set `SERVICE_LOGSTASH_FORWARDER` equal to `disabled` and disable or minimize file logging while adjusting stdout/stderr to your needs.


#### Redpill
Redpill is a small script that performs status checks on services managed through supervisor. In the event of a failed service (FATAL) Redpill optionally runs a cleanup script and then terminates the parent supervisor process. Redpill itself is located at `/opt/scripts/redpill.sh`.


---
---

### Helper Functions

---

#### cidr2mask
**Name:** `__cidr2mask`
**Usage:** `__cidr2mask <cidr_value>`

**Description:**
Converts a cidr mask to a subnet mask and echo's it's value.


---

#### mask2cidr
**Name:** `__mask2cidr`
**Usage:** `__mask2cidr <subnet_maks>`

**Description:**
Converts a subnet mask to cidr notation and echo's it's value.


---

#### escape_svsr_txt
**Name:** `__escape_svsr_txt`
**Usage:** `__escape_svsr_txt <string>`

**Description:**
Escapes the passed string for use in a supervisor command and echo's it's value.


---
---

### Supervisor Config Functions

---

#### config_service_keepalived
**Name:** `config_service_keepalived`
**Usage:** `__config_service_keepalived`
**Supervisor Config:** `/etc/supervisor/conf.d/100-keepalived.conf`

**Description:**
Manages the supervisor config for keepalived.

| **Variable**              | **Default**                                           |
|---------------------------|-------------------------------------------------------|
| `SERVICE_KEEPALIVED`      |                                                       |
| `SERVICE_KEEPALIVED_CONF` | `/etc/keepalived/keepalived.conf`                     |
| `SERVICE_KEEPALIVED_CMD`  | `/usr/sbin/keepalived -n -f $SERVICE_KEEPALIVED_CONF` |


##### Description

* `SERVICE_KEEPALIVED` - Enables or disables the Keepalived service. Set automatically depending on the `ENVIRONMENT`. See the Environment section.  (**Options:** `enabled` or `disabled`)

* `SERVICE_KEEPALIVED_CONF` - The path to keepalived config.

* `SERVICE_KEEPALIVED_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.

---

#### config_service_logrotate
**Name:** `config_service_logrotate`
**Usage:** `__config_service_logrotate`
**Supervisor Config:** `/etc/supervisor/conf.d/990-logrotate.conf`

**Description**
Manages the supervisor config for logrotate bash helper script.

| **Variable**                 | **Default**                         |
|------------------------------|-------------------------------------|
| `SERVICE_LOGROTATE`          |                                     |
| `SERVICE_LOGROTATE_INTERVAL` |                                     |
| `SERVICE_LOGROTATE_CONF`     |                                     |
| `SERVICE_LOGROTATE_SCRIPT`   |                                     |
| `SERVICE_LOGROTATE_FORCE`    |                                     |
| `SERVICE_LOGROTATE_VERBOSE`  |                                     |
| `SERVICE_LOGROTATE_DEBUG`    |                                     |
| `SERVICE_LOGROTATE_CMD`      | `/opt/scripts/logrotate.sh <flags>` |

##### Description

* `SERVICE_LOGROTATE` - Enables or disables the nslcd service. (**Options:** `enabled` or `disabled`)

* `SERVICE_LOGROTATE_INTERVAL` - The interval in seconds between runs logrotate (default set in script to `3600`).

* `SERVICE_LOGROTATE_CONF` - The path to the logrotate configuration file.

* `SERVICE_LOGROTATE_SCRIPT` - The path to a script that should be executed instead of calling logrotate directly.

* `SERVICE_LOGROTATE_FORCE` - If set, enables forcing of log rotation.

* `SERVICE_LOGROTATE_VERBOSE` - If set, enables verbose log output.

* `SERVICE_LOGROTATE_DEBUG` - If set, enabled debug log output.

*  `SERVICE_LOGROTATE_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.


---

#### config_service_logstash_forwarder
**Name:** `config_service_logstash_forwarder`
**Usage:** `__config_service_logstash_forwarder`
**Supervisor Config:** `/etc/supervisor/conf.d/900-logstash-forwarder.conf`

**Description**
Manages the supervisor config for logstash-forwarder and modifies the configuration if certain variables are supplied.


| **Variable**                         | **Default**                                                                              |
|--------------------------------------|------------------------------------------------------------------------------------------|
| `SERVICE_LOGSTASH_FORWARDER`         |                                                                                          |
| `SERVICE_LOGSTASH_FORWARDER_CONF`    |                                                                                          |
| `SERVICE_LOGSTASH_FORWARDER_ADDRESS` |                                                                                          |
| `SERVICE_LOGSTASH_FORWARDER_CERT`    |                                                                                          |
| `SERVICE_LOGSTASH_FORWARDER_CMD`     | `/opt/logstash-forwarder/logstash-forwarder -config="${SERVICE_LOGSTASH_FOWARDER_CONF}"` |



* `SERVICE_LOGSTASH_FORWARDER` - Enables or Disables the Logstash-Forwarder service.

* `SERVICE_LOGSTASH_FORWARDER_CONF` - The path to Logstash-Forwarder configuration file.

* `SERVICE_LOGSTASH_FORWARDER_ADDRESS` - The address of the Logstash server.

* `SERVICE_LOGSTASH_FORWARDER_CERT` - The path to the Logstash-Forwarder server certificate.

* `SERVICE_LOGSTASH_FORWARDER_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.


---

#### config_service_nslcd
**Name:** `config_service_nslcd`
**Usage:** `__config_service_nslcd`
**Supervisor Config:** `/etc/supervisor/conf.d/200-nslcd.conf`

**Description**
Manages the supervisor config for nslcd.

| **Variable**        | **Default**         |
|---------------------|---------------------|
| `SERVICE_NSLCD`     |                     |
| `SERVICE_NSLCD_CMD` | `usr/sbin/nslcd -n` |

##### Description

* `SERVICE_NSLCD` - Enables or disables the nslcd service

*  `SERVICE_NSLCD_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.


---

#### config_service_redpill
**Name:** `config_service_redpill`
**Usage:** `__config_service_redpill`
**Supervisor Config:** `/etc/supervisor/conf.d/999-redpill.conf`

**Description**
Manages the supervisor config for redpill in addition to generating the config


| Variable                   | Default         |
|----------------------------|-----------------|
| `SERVICE_REDPILL`          |                 |
| `SERVICE_REDPILL_MONITOR`  |                 |
| `SERVICE_REDPILL_INTERVAL` |                 |
| `SERVICE_REDPILL_CLEANUP`  |                 |
| `SERVICE_REDPILL_CMD`      | See Description |

##### Description

* `SERVICE_REDPILL` - Enables or disables the Redpill service. Set automatically depending on the `ENVIRONMENT`. See the Environment section.  (**Options:** `enabled` or `disabled`)

* `SERVICE_REDPILL_MONITOR` - The name of the supervisord service(s) that the Redpill service check script should monitor. 

* `SERVICE_REDPILL_INTERVAL` - The interval in which Redpill polls supervisor for status checks. (Default for the script is 30 seconds)

* `SERVICE_REDPILL_CLEANUP` - The path to the script that will be executed upon container termination. For OpenVPN this should clear any iptables rules from the host.

* `SERVICE_REDPILL_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information. The command is assembled in the form of: `/opt/scripts/redpill.sh -c <cleanup_script> -i <interval> -s <service names(s)>` with each option being tacked on only if it is specified via the above environment variables.


---

#### config_service_rsyslog
**Name:** `config_service_rsyslog`
**Usage:** `__config_service_rsyslog`
**Supervisor Config:** `/etc/supervisor/conf.d/000-redpill.conf`

**Description**
Manages the supervisor config for rsyslog. Rsyslog is only enabled when other applications of services cannot log without it.

##### Defaults

| **Variable**                      | **Default**                                      |
|-----------------------------------|--------------------------------------------------|
| `SERVICE_RSYSLOG`                 |                                                  |
| `SERVICE_RSYSLOG_CONF`            | `/etc/rsyslog.conf`                              |
| `SERVICE_RSYSLOG_CMD`             | `/usr/sbin/rsyslogd -n -f $SERVICE_RSYSLOG_CONF` |

##### Description

* `SERVICE_RSYSLOG` - Enables or disables the rsyslog service. This will automatically be set depending on what other services are enabled. (**Options:** `enabled` or `disabled`)

* `SERVICE_RSYSLOG_CONF` - The path to the rsyslog configuration file.

* `SERVICE_RSYSLOG_CMD` -  The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.

---
---

### Application Config Functions

---

#### config_keepalived
**Name:** `config_keepalived`
**Usage:** `__config_keepalived`

**Description:**
If keepalived has been enabled via `__config_service_keepalived` This function will auto generate the keepalived config based on various environment variables.

##### Keepalived Auto Configuration Options and Defaults


| **Variable**                                | **Default**                        |
|---------------------------------------------|------------------------------------|
| `KEEPALIVED_STATE`                          | `MASTER`                           |
| `KEEPALIVED_PRIORITY`                       | `200`                              |
| `KEEPALIVED_INTERFACE`                      | `eth0`                             |
| `KEEPALIVED_VIRTUAL_ROUTER_ID`              | `1`                                |
| `KEEPALIVED_ADVERT_INT`                     | `1`                                |
| `KEEPALIVED_AUTH_PASS`                      | `pwd$KEEPALIVED_VIRTUAL_ROUTER_ID` |
| `KEEPALIVED_VRRP_UNICAST_BIND`              |                                    |
| `KEEPALIVED_VRRP_UNICAST_PEER`              |                                    |
| `KEEPALIVED_TRACK_INTERFACE_###`            |                                    |
| `KEEPALIVED_VIRTUAL_IPADDRESS_###`          |                                    |
| `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###` |                                    |


##### Description

* `KEEPALIVED_AUTOCONF` - Enables or Disables Keepalived autoconfiguration. (**Options:** `enabled` or `disabled`)

* `KEEPALIVED_STATE` - Defines the server role as Master or Backup. (**Options:** `MASTER` or `BACKUP`).

* `KEEPALIVED_PRIORITY` - Election value, the server configured with the highest priority will become the Master.

* `KEEPALIVED_INTERFACE` - The host interface that keepalived will monitor and use for VRRP traffic.

* `KEEPALIVED_VIRTUAL_ROUTER_ID` - A unique number from 0 to 255 that should identify the VRRP group. Master and Backup should have the same value. Multiple instances of keepalived can be run on the same host, but each pair **MUST** have a unique virtual router id.

* `KEEPALIVED_ADVERT_INT` - The VRRP advertisement interval (in seconds).

* `KEEPALIVED_AUTH_PASS` - A shared password used to authenticate each node in a VRRP group (**Note:** If password is longer than 8 characters, only the first 8 characters are used).

* `KEEPALIVED_VRRP_UNICAST_BIND` - The IP on the host that the keepalived daemon should bind to. **Note:** If not specified, it will be the first IP bound to the interface specified in `$KEEPALIVED_INTERFACE`

* `KEEPALIVED_VRRP_UNICAST_PEER` - The IP of the peer in the VRRP group. (**Required**)

* `KEEPALIVED_TRACK_INTERFACE_###` - An interface that's state should be monitored (e.g. eth0). More than one can be supplied as long as the variable name ends in a number from 0-999.

* `KEEPALIVED_VIRTUAL_IPADDRESS_###` - An instance of an address that will be monitored and failed over from one host to another. These should be a quoted string in the form of: `<IPADDRESS>/<MASK> brd <BROADCAST_IP> dev <DEVICE> scope <SCOPE> label <LABEL>` At a minimum the ip address, mask and device should be specified e.g. `KEEPALIVED_VIRTUAL_IPADDRESS_1="10.10.0.2/24 dev eth0"`. More than one can be supplied as long as the variable name ends in a number from 0-999. **Note:** Keepalived has a hard limit of **20** addresses that can be monitored. More can be failed over with the monitored addresses via `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###`. (**Required**)

* `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###` - An instance of an address that will be failed over with the monitored addresses supplied via `KEEPALIVED_VIRTUAL_IPADDRESS_###`.  These should be a quoted string in the form of: `<IPADDRESS>/<MASK> brd <BROADCAST_IP> dev <DEVICE> scope <SCOPE> label <LABEL>` At a minimum the ip address, mask and device should be specified e.g. `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_1="172.16.1.20/24 dev eth1"`. More than one can be supplied as long as the variable name ends in a number from 0-999.

##### Example Autogenerated Keepalived Master Config
```
vrrp_instance MAIN {
  state MASTER
  interface eth0
  vrrp_unicast_bind 10.10.0.21
  vrrp_unicast_peer 10.10.0.22
  virtual_router_id 2
  priority 200
  advert_int 1
  authentication {
    auth_type PASS
    auth_pass pwd1
  }
  virtual_ipaddress {
    10.10.0.2/24 dev eth0
  }
  virtual_ipaddress_excluded {
    172.16.1.20/24 dev eth1
  }
  track_interface {
    eth0
    eth1
  }
}

```

##### Example Autogenerated Keepalived Backup Config
```
vrrp_instance MAIN {
  state BACKUP
  interface eth0
  vrrp_unicast_bind 10.10.0.22
  vrrp_unicast_peer 10.10.0.21
  virtual_router_id 2
  priority 100
  advert_int 1
  authentication {
    auth_type PASS
    auth_pass pwd1
  }
  virtual_ipaddress {
    10.10.0.2/24 dev eth0
  }
  virtual_ipaddress_excluded {
    172.16.1.20/24 dev eth1
  }
  track_interface {
    eth0
    eth1
  }
}

```


