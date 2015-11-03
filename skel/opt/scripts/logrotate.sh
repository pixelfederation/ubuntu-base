#!/bin/bash

_terminator() {
    echo "[$(date)][Logrotate] SIGNAL trapped, terminating background sleep pid $1."
    kill $1
    exit
}


usage() {
cat << _EOF_
logrotate.sh - Small wrapper script for logrotate.
-i | --interval     The interval in seconds that logrotate should run.
-c | --config       Path to the logrotate config.
-f | --force        Forces log rotation.
-v | --verbose      Display verbose output.
-d | --debug        Enabled debugging, and implies verbose output. No state file changes.
-h | --help         This usage text.
_EOF_
exit
}


main() {

  if [[ $# -eq 0 ]]; then
    usage
  fi

  logrotate_cmd="/usr/sbin/logrotate "

  while [[ $# -gt 0 ]]; do
    i=$1
    case $i in
    -i|--interval)
      logrotate_interval="$2"
      shift
      ;;
    -c|--config)
      logrotate_config="$2"
      shift
      ;;
    -f|--force)
      logrotate_cmd+="-f "
      ;;
    -v|--verbose)
      logrotate_cmd+="-v "
      ;;
    -d|--debug)
      logrotate_cmd+="-d "
      ;;
    -h|--help|*)
      usage
      ;;
    esac
    shift
  done

  if [[ ! "$logrotate_config" && -f "$logrotate_config" ]]; then
      echo "[$(date)][Logrotate] No config specified. Terminating logrotate script."
      exit
  fi

  logrotate_cmd+="$logrotate_config"
  logrotate_interval=${logrotate_interval:-3600}

  echo "[$(date)][Logrotate] Starting Logrotate service."
  echo "[$(date)][Logrotate] Logrotate config: $logrotate_config"
  echo "[$(date)][Logrotate] Logrotate command: $logrotate_cmd"
  echo "[$(date)][Logrotate] Interval: $logrotate_interval (seconds)"

  sleep $logrotate_interval & sleep_pid=$!
  trap "_terminator $sleep_pid" INT KILL TERM
  wait

  while true; do
    "$logrotate_cmd"
    sleep $logrotate_interval & sleep_pid=$!
    trap "_terminator $sleep_pid" INT KILL TERM
    wait
  done
}


main "$@"
