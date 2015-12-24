#!/bin/bash
#
# About:
# A collection of helpful functions for use with configuring
# containers at runtime.
#
# Note: All functions begin with '__'
# 
# Functions:
# Helper Functions
# - cidr2mask
# - mask2cidr
# Config Helper Functions
# - escape_svsr_txt
# Supervisor Service Config Functions
# - config_service_keepalived
# - config_service_logrotate
# - config_service_logstash_forwarder
# - config_service_nslcd
# - config_service_redpill
# - config_service_rsyslog
# Shared Application Configuration Functions
# - config_keepalived


########## Helper Functions ##########

##### cidr2mask #####
# Takes a cidr value (number less than 32) and converts it 
# to string in proper netmask form.
##### cidr2mask #####

__cidr2mask() {
  if ! [[ "$1" =~ ^[0-9]+$ && $1 -le 32 ]]; then
    echo "[$(date)][__cidr2mask] cidr value not valid: $1"
    return 1
  fi

  local smask=""
  local let base_octet=$1/8
  local let mod_octet=$1%8
  for octet in {0..3}; do
    if [[ $octet -lt $base_octet ]]; then
      smask+="255"
    elif [[ $octet -eq $base_octet ]]; then
        smask+="$((256 - 2**(8-$mod_octet)))"
    else
      smask+="0"
    fi

    if [[ $octet -lt 3 ]]; then
        smask+="."
    fi
  done

  echo "$smask"

  return 0
}


##### mask2cidr #####
# Takes a string netmask value and converts it to a valid
# cidr form.
##### mask2cidr #####

__mask2cidr() {
  local cidrbits=0
  for octet in $(echo "$1" | tr "." "\n"); do
    case $octet in
      255) let cidrbits+=8;;
      254) let cidrbits+=7;;
      252) let cidrbits+=6;;
      248) let cidrbits+=5;;
      240) let cidrbits+=4;;
      224) let cidrbits+=3;;
      192) let cidrbits+=2;;
      128) let cidrbits+=1;;
      0);;
      *) echo "[$(date)][__mask2cidr] Invalid mask octet in: $1"; return 1;;
    esac
  done

  echo $cidrbits

  return 0
}


########## Config Helper Functions ##########

##### escape_svsr_txt #####
# Returns a string properly escaped for use in a supervisor config
##### escape_svsr_txt #####

__escape_svsr_txt() {
  local escaped_text="$1"
  if [[ $(echo "$escaped_text" | grep -c "%") -gt 0 ]]; then
    escaped_text="${escaped_text//%/%%}"
  fi
  echo "$escaped_text"

  return 0
}


########## Supervisor Service Config Functions ##########

##### config_service_keepalived #####
# Configures the supervisor config for keepalived.
# No configuration parameters needed to generate config.
# SERVICE_KEEPALIVED_CMD - The escaped command passed to supervisor
##### config_service_keepalived #####

__config_service_keepalived() {
  case "${SERVICE_KEEPALIVED,,}" in
    enabled)
      if [[ -f /etc/supervisor/conf.d/100-keepalived.disabled ]]; then
        mv /etc/supervisor/conf.d/100-keepalived.disabled /etc/supervisor/conf.d/100-keepalived.conf
      fi

      export SERVICE_KEEPALIVED_CONF=${SERVICE_KEEPALIVED_CONF:-/etc/keepalived/keepalived.conf}
      local keepalived_cmd="/usr/sbin/keepalived -n -f $SERVICE_KEEPALIVED_CONF"
      export SERVICE_KEEPALIVED_CMD=${SERVICE_KEEPALIVED_CMD:-"$(__escape_svsr_txt "$keepalived_cmd")"}

      echo "[$(date)][Keepalived][Status] Enabled"
      echo "[$(date)][Keepalived][Start-Command] $SERVICE_KEEPALIVED_CMD"
      ;;
    disabled)
      if [[ -f /etc/supervisor/conf.d/100-keepalived.conf ]]; then
        mv /etc/supervisor/conf.d/100-keepalived.conf /etc/supervisor/conf.d/100-keepalived.disabled
      fi

      echo "[$(date)][Keepalived][Status] Disabled"
      ;;
    *)
      if [[ -f /etc/supervisor/conf.d/100-keepalived.conf ]]; then
        mv /etc/supervisor/conf.d/100-keepalived.conf /etc/supervisor/conf.d/100-keepalived.disabled
      fi

      echo "[$(date)][Keepalived] Unrecongized Option. Defaulting to disabled."
      echo "[$(date)][Keepalived][Status] Disabled"
      ;;
  esac

  return 0
}

##### config_service_logrotate #####
# Configures supervisor config for logrotate script
# SERVICE_LOGROTATE_INTERNVAL - Interval at which logrotate will be run
# SERVICE_LOGROTATE_CONF - path to logrotate config.
# SERVICE_LOGROTATE_SCRIPT - path to alternate script to execute instead of logrotate.
# SERVICE_LOGROTATE_FORCE - Force log rotation.
# SERVICE_LOGROTATE_VERBOSE - if set, enable verbose log output.
# SERVICE_LOGROTATE_DEBUG - if set, disable status file logging and output all logs to console.
# SERVICE_LOGROTATE_CMD - The escaped command passed to supervisor.
##### config_service_logrotate #####

__config_service_logrotate() {
  case "${SERVICE_LOGROTATE,,}" in
    enabled)
      if [[ -f /etc/supervisor/conf.d/990-logrotate.disabled ]]; then
        mv /etc/supervisor/conf.d/990-logrotate.disabled /etc/supervisor/conf.d/990-logrotate.conf
      fi

      local logrotate_cmd="/opt/scripts/logrotate.sh"
      echo "[$(date)][Logrotate][Status] Enabled"  

      if [[ $SERVICE_LOGROTATE_INTERVAL ]]; then
        logrotate_cmd+=" -i $SERVICE_LOGROTATE_INTERVAL"
        echo "[$(date)][Logrotate][Interval] $SERVICE_LOGROTATE_INTERVAL"
      fi

      if [[ $SERVICE_LOGROTATE_SCRIPT ]]; then
        logrotate_cmd+=" -s $SERVICE_LOGROTATE_SCRIPT"
      else
        if [[ $SERVICE_LOGROTATE_FORCE ]]; then
          logrotate_cmd+=" -f"
        fi
        if [[ $SERVICE_LOGROTATE_VERBOSE ]]; then
          logrotate_cmd+=" -v"
        fi
        if [[ $SERVICE_LOGROTATE_DEBUG ]]; then
          logrotate_cmd+=" -d"
        fi
        if [[ $SERVICE_LOGROTATE_CONF ]]; then
          logrotate_cmd+=" -c $SERVICE_LOGROTATE_CONF"
        fi
      fi

      logrotate_cmd="$(__escape_svsr_txt "$logrotate_cmd")"
      export SERVICE_LOGROTATE_CMD=${SERVICE_LOGROTATE_CMD:-"$logrotate_cmd"}
      
      echo "[$(date)][Logrotate][Start-Command] $SERVICE_LOGROTATE_CMD"
      ;;
    disabled)
      if [[ -f /etc/supervisor/conf.d/990-logrotate.conf ]]; then
        mv /etc/supervisor/conf.d/990-logrotate.conf /etc/supervisor/conf.d/990-logrotate.disabled
      fi
      echo "[$(date)][Logrotate][Status] Disabled"
      ;;
    *)
      if [[ -f /etc/supervisor/conf.d/990-logrotate.conf ]]; then
        mv /etc/supervisor/conf.d/990-logrotate.conf /etc/supervisor/conf.d/990-logrotate.disabled
      fi
      echo "[$(date)][Logrotate][Init] Unrecognized Option. Defaulting to disabled."
      echo "[$(date)][Logrotate][Status] Disabled."
      ;;
  esac

  return 0
}


##### config_service_logstash_forwarder #####
# Configures both the supervisor config and components of the logstash-forwarder config itself
# SERVICE_LOGSTASH_FORWARDER_CONF - The path to the logstash forwarder configuration.
#  - default - /opt/logstash-forwarder/logstash-forwarder.conf
# SERVICE_LOGSTASH_FORWARDER_CMD - The escaped command passed to supervisor
#  - default - /opt/logstash-forwarder/bin/logstash-forwarder -config="$SERVICE_LOGSTASH_FORWARDER_CONF"
# 
# Variables sed'ed into the logstash-forwarder configuration:
# SERVICE_LOGSTASH_FORWARDER_ADDRESS - a single address specifying the logstash-forwarder host (if defined at all)
# SERVICE_LOGSTASH_FORWARDER_CERT - a path to a cert for use with logstash-forwarder (if defined at all)
# APP_NAME - The primary application name
# ENVIRONMENT - The environment in which the application is running
# PARENT_HOST - The parent host of the container
##### config_service_logstash_forwarder #####


__config_service_logstash_forwarder() {
  case "${SERVICE_LOGSTASH_FORWARDER,,}" in
    enabled)
      if [[ -f /etc/supervisor/conf.d/900-logstash-forwarder.disabled ]]; then
        mv /etc/supervisor/conf.d/900-logstash-forwarder.disabled /etc/supervisor/conf.d/900-logstash-forwarder.conf
      fi

      export SERVICE_LOGSTASH_FORWARDER_CONF=${SERVICE_LOGSTASH_FORWARDER_CONF:-/opt/logstash-forwarder/logstash-forwarder.conf}
      local logstash_forwarder_cmd="$(__escape_svsr_txt "/opt/logstash-forwarder/bin/logstash-forwarder -config=\"$SERVICE_LOGSTASH_FORWARDER_CONF\"")"
      export SERVICE_LOGSTASH_FORWARDER_CMD=${SERVICE_LOGSTASH_FORWARDER_CMD:-"$logstash_forwarder_cmd"}

      #ONLY works if going to a single address.
      if [[ "$SERVICE_LOGSTASH_FORWARDER_ADDRESS" ]]; then
        sed -i -r -e "s|(\"servers\":\s*\[\s*\")\S*(\"\s*\])|\1$LOGSTASH_FORWARDER_ADDRESS\2|g" "$SERVICE_LOGSTASH_FORWARDER_CONF"
      fi
      if [[ "$SERVICE_LOGSTASH_FORWARDER_CERT" ]]; then
        sed -i -e "s|\"ssl ca\":\s* \"\S*\"|\"ssl ca\": \"$LOGSTASH_FORWARDER_CERT\"|g" "$SERVICE_LOGSTASH_FORWARDER_CONF"
      fi
      if [[ "$APP_NAME" ]]; then
        sed -i -e "s|\"app_name\":\s* \"\S*\"|\"app_name\": \"$APP_NAME\"|g" "$SERVICE_LOGSTASH_FORWARDER_CONF"
      fi
      if [[ "$ENVIRONMENT" ]]; then
        sed -i -e "s|\"environment\":\s* \"\S*\"|\"environment\": \"$ENVIRONMENT\"|g" "$SERVICE_LOGSTASH_FORWARDER_CONF"
      fi
      if [[ "$PARENT_HOST" ]]; then
        sed -i -e "s|\"parent_host\":\s* \"\S*\"|\"parent_host\": \"$PARENT_HOST\"|g" "$SERVICE_LOGSTASH_FORWARDER_CONF"
      fi

      echo "[$(date)][Logstash-Forwarder][Status] Enabled"
      echo "[$(date)][Logstash-Forwarder][Config] $SERVICE_LOGSTASH_FORWARDER_CONF"
      echo "[$(date)][Logstash-Forwarder][Start-Command] $SERVICE_LOGSTASH_FORWARDER_CMD"
      ;;
    disabled)
      if [[ -f /etc/supervisor/conf.d/900-logstash-forwarder.conf ]]; then
        mv /etc/supervisor/conf.d/900-logstash-forwarder.conf /etc/supervisor/conf.d/900-logstash-forwarder.disabled
      fi

      echo "[$(date)][Logstash-Forwarder][Status] Disabled"
      ;;
    *)
      if [[ -f /etc/supervisor/conf.d/900-logstash-forwarder.conf ]]; then
        mv /etc/supervisor/conf.d/900-logstash-forwarder.conf /etc/supervisor/conf.d/900-logstash-forwarder.disabled
      fi

      echo "[$(date)][Logstash-Forwarder][Init] Unrecognized Option. Defaulting to disabled."
      echo "[$(date)][Logstash-Forwarder][Status] Disabled"
      ;;
  esac

  return 0
}

##### config_service_nslcd #####
# Configures supervisor config for libpam-ldapd (nslcd)
# SERVICE_NSLCD_CMD - The escaped command passed to supervisor
##### config_service_nslcd #####

__config_service_nslcd() {
  case "${SERVICE_NSLCD,,}" in
    enabled)
      if [[ -f /etc/supervisor/conf.d/200-nslcd.disabled ]]; then
          mv /etc/supervisor/conf.d/200-nslcd.disabled /etc/supervisor/conf.d/200-nslcd.conf
      fi

      export SERVICE_NSLCD_CMD=${SERVICE_NSLCD_CMD:-"/usr/sbin/nslcd -n"}
      echo "[$(date)][Nslcd][Status] Enabled"
      echo "[$(date)][Nslcd][Start-Command] $SERVICE_NSLCD_CMD"
      ;;
    disabled)
      if [[ -f /etc/supervisor/conf.d/200-nslcd.conf ]]; then
        mv /etc/supervisor/conf.d/200-nslcd.conf /etc/supervisor/conf.d/200-nslcd.disabled
      fi

      echo "[$(date)][Nslcd][Status] Disabled"
      ;;
    *)
      if [[ -f /etc/supervisor/conf.d/200-nslcd.conf ]]; then
        mv /etc/supervisor/conf.d/200-nslcd.conf /etc/supervisor/conf.d/200-nslcd.disabled
      fi

      echo "[$(date)][Nslcd][Init] Unrecognized Option. Defaulting to disabled."
      echo "[$(date)][Nslcd][Status] Disabled"
      ;;
  esac
}


##### config_service_redpill #####
# Configures supervisor config for redpill healthcheck script
# SERVICE_REDPILL_CLEANUP - Path to a script that should be executed upon container termination (optional)
# SERVICE_REDPILL_INTERNVAL - Interval at which redpill checks the status of services (optional)
# SERVICE_REDPILL_MONITOR - comma delimited list of services redpill should monitor
# SERVICE_REDPILL_CMD - The escaped command passed to supervisor.
##### config_service_redpill #####

__config_service_redpill() {
  case "${SERVICE_REDPILL,,}" in
    enabled)
      if [[ -f /etc/supervisor/conf.d/999-redpill.disabled ]]; then
        mv /etc/supervisor/conf.d/999-redpill.disabled /etc/supervisor/conf.d/999-redpill.conf
      fi

      local redpill_cmd="/opt/scripts/redpill.sh"
      echo "[$(date)][Redpill][Status] Enabled"  

      if [[ $SERVICE_REDPILL_CLEANUP ]]; then
        redpill_cmd+=" -c \"$SERVICE_REDPILL_CLEANUP\""
        echo "[$(date)][Redpill][Cleanup-Script] $SERVICE_REDPILL_CLEANUP"
      fi
      if [[ $SERVICE_REDPILL_INTERVAL ]]; then
        redpill_cmd+=" -i $SERVICE_REDPILL_INTERVAL"
        echo "[$(date)][Redpill][Interval] $SERVICE_REDPILL_INTERVAL"
      fi
      if [[ $SERVICE_REDPILL_MONITOR ]]; then
        redpill_cmd+=" -s $SERVICE_REDPILL_MONITOR"
        echo "[$(date)][Redpill][Monitoring] ${SERVICE_REDPILL_MONITOR//,/ }"
      fi

      redpill_cmd="$(__escape_svsr_txt "$redpill_cmd")"
      export SERVICE_REDPILL_CMD=${SERVICE_REDPILL_CMD:-"$redpill_cmd"}
      
      echo "[$(date)][Redpill][Start-Command] $SERVICE_REDPILL_CMD"
      ;;
    disabled)
      if [[ -f /etc/supervisor/conf.d/999-redpill.conf ]]; then
        mv /etc/supervisor/conf.d/999-redpill.conf /etc/supervisor/conf.d/999-redpill.disabled
      fi
      echo "[$(date)][Redpill][Status] Disabled"
      ;;
    *)
      if [[ -f /etc/supervisor/conf.d/999-redpill.conf ]]; then
        mv /etc/supervisor/conf.d/999-redpill.conf /etc/supervisor/conf.d/999-redpill.disabled
      fi
      echo "[$(date)][Redpill][Init] Unrecognized Option. Defaulting to disabled."
      echo "[$(date)][Redpill][Status] Disabled."
      ;;
  esac

  return 0
}


##### config_service_rsyslog #####
# Configures rsyslog for log services. In general, this service should not 
# be override by hand. It should just be enabled if services use them i.e.
# keepalived or haproxy.
# SERVICE_RSYSLOG_CONF - The path to the rsyslog Configuration File
# SERVICE_RSYSLOG_CMD - The escaped command passed to supervisor
##### config_service_rsyslog #####

__config_service_rsyslog() {
  case "${SERVICE_RSYSLOG,,}" in
    enabled)
      if [[ -f /etc/supervisor/conf.d/000-rsyslog.disabled ]]; then
          mv /etc/supervisor/conf.d/000-rsyslog.disabled /etc/supervisor/conf.d/000-rsyslog.conf
      fi

      export SERVICE_RSYSLOG_CONF=${SERVICE_RSYSLOG_CONF:-/etc/rsyslog.conf}
      local rsyslog_cmd="/usr/sbin/rsyslogd -n -f $SERVICE_RSYSLOG_CONF"
      export SERVICE_RSYSLOG_CMD=${SERVICE_RSYSLOG_CMD:-"$(__escape_svsr_txt "$rsyslog_cmd")"}

      echo "[$(date)][Rsyslog][Status] Enabled"
      echo "[$(date)][Rsyslog][Start-Command] $SERVICE_RSYSLOG_CMD"
      ;;
    disabled)
      if [[ -f /etc/supervisor/conf.d/000-rsyslog.conf ]]; then
        mv /etc/supervisor/conf.d/000-rsyslog.conf /etc/supervisor/conf.d/000-rsyslog.disabled
      fi

      echo "[$(date)][Rsyslog][Status] Disabled"
      ;;
    *)
      if [[ -f /etc/supervisor/conf.d/000-rsyslog.conf ]]; then
        mv /etc/supervisor/conf.d/000-rsyslog.conf /etc/supervisor/conf.d/000-rsyslog.disabled
      fi

      echo "[$(date)][Rsyslog][Init] Unrecognized Option. Defaulting to disabled."
      echo "[$(date)][Rsyslog][Status] Disabled"
      ;;
  esac
}


########## Shared Application Configuration Functions ##########

__config_keepalived() {
  if [[ ! $KEEPALIVED_VRRP_UNICAST_PEER ]]; then
    echo "[$(date)][KEEPALIVED] KEEPALIVED_VRRP_UNICAST_PEER not set."
    return 1
  fi
  if [[ ! $(compgen -A variable | grep -E "KEEPALIVED_VIRTUAL_IPADDRESS_[0-9]{1,3}") ]]; then
    echo "[$(date)][KEEPALIVED] No KEEPALIVED_VIRTUAL_IPADDRESS_ varibles detected."
    return 1
  fi

  export KEEPALIVED_STATE=${KEEPALIVED_STATE:-MASTER}

  if [[ "${KEEPALIVED_STATE^^}" == "MASTER" ]]; then
    export KEEPALIVED_PRIORITY=${KEEPALIVED_PRIORITY:-200}
  elif [[ "${KEEPALIVED_STATE^^}" == "BACKUP" ]]; then
    export KEEPALIVED_PRIORITY=${KEEPALIVED_PRIORITY:-100}
  fi

  export KEEPALIVED_INTERFACE=${KEEPALIVED_INTERFACE:-eth0}
  export KEEPALIVED_VIRTUAL_ROUTER_ID=${KEEPALIVED_VIRTUAL_ROUTER_ID:-1}
  export KEEPALIVED_ADVERT_INT=${KEEPALIVED_ADVERT_INT:-1}
  export KEEPALIVED_AUTH_PASS=${KEEPALIVED_AUTH_PASS:-"pwd$KEEPALIVED_VIRTUAL_ROUTER_ID"}

  if [[ ! $KEEPALIVED_VRRP_UNICAST_BIND ]]; then
    export KEEPALIVED_VRRP_UNICAST_BIND="$(ip addr show "$KEEPALIVED_INTERFACE" | \
      grep -m 1 -P -o '(?<=inet )[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')"
  fi
  
  echo "vrrp_instance MAIN {" > "$SERVICE_KEEPALIVED_CONF"
  echo "  state $KEEPALIVED_STATE" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  interface $KEEPALIVED_INTERFACE" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  vrrp_unicast_bind $KEEPALIVED_VRRP_UNICAST_BIND" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  vrrp_unicast_peer $KEEPALIVED_VRRP_UNICAST_PEER" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  virtual_router_id $KEEPALIVED_VIRTUAL_ROUTER_ID" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  priority $KEEPALIVED_PRIORITY" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  advert_int $KEEPALIVED_ADVERT_INT" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  authentication {" >> "$SERVICE_KEEPALIVED_CONF"
  echo "    auth_type PASS" >> "$SERVICE_KEEPALIVED_CONF"
  echo "    auth_pass $KEEPALIVED_AUTH_PASS" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  }" >> "$SERVICE_KEEPALIVED_CONF"
  echo "  virtual_ipaddress {" >> "$SERVICE_KEEPALIVED_CONF"
  for vip in $(compgen -A variable | grep -E "KEEPALIVED_VIRTUAL_IPADDRESS_[0-9]{1,3}"); do
    echo "    ${!vip}" >> "$SERVICE_KEEPALIVED_CONF"
  done
  echo "  }" >> "$SERVICE_KEEPALIVED_CONF"

  if [[ $(compgen -A variable | grep -E "KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_[0-9]{1,3}") ]]; then
    echo "  virtual_ipaddress_excluded {" >> "$SERVICE_KEEPALIVED_CONF"
    for evip in $(compgen -A variable | grep -E "KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_[0-9]{1,3}"); do
      echo "    ${!evip}" >> "$SERVICE_KEEPALIVED_CONF"
    done
    echo "  }" >> "$SERVICE_KEEPALIVED_CONF"
  fi

  if [[ $(compgen -A variable | grep -E "KEEPALIVED_TRACK_INTERFACE_[0-9]{1,3}") ]]; then
    echo "  track_interface {" >> "$SERVICE_KEEPALIVED_CONF"
    for interface in $(compgen -A variable | grep -E "KEEPALIVED_TRACK_INTERFACE_[0-9]{1,3}"); do
      echo "    ${!interface}" >> "$SERVICE_KEEPALIVED_CONF"
    done
    echo "  }" >> "$SERVICE_KEEPALIVED_CONF"
  else
    echo "  track_interface {" >> "$SERVICE_KEEPALIVED_CONF"
    echo "    $KEEPALIVED_INTERFACE" >> "$SERVICE_KEEPALIVED_CONF"
    echo "}" >> "$SERVICE_KEEPALIVED_CONF"
 fi

  echo "}" >> "$SERVICE_KEEPALIVED_CONF"

  return 0
}

