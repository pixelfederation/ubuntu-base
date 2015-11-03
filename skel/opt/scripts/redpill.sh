#!/bin/bash

_terminator() {
    echo "[$(date)][Redpill] SIGNAL trapped, terminating background sleep pid $1."
    if [[ $cleanup_script ]]; then
      cleanup "$2"
    fi
    kill $1
    exit
}

cleanup() {
  "$1"
}

usage() {
  cat << _EOF_
Redpill - Supervisor status monitor. Terminates the supervisor process if any specified service enters a FATAL state.

-c | --cleanup    Optional path to cleanup script that should be executed upon exit.
-h | --help       This help text.
-i | --interval   Optional interval at which the service check is performed in seconds. (Default: 30)
-s | --service    A comma delimited list of the supervisor service names that should be monitored.
_EOF_
  exit
}



main() {

  services=()

  if [[ $# -eq 0 ]]; then
    usage
  fi

  while [[ $# -gt 0 ]]; do
    i=$1
    case $i in
      -c|--cleanup)
        cleanup_script="$2"
        shift
        ;;
      -i|--interval)
        interval="$2"
        shift
        ;;
      -s|--service)
        services+=(${2//,/ })
        shift
        ;;
      -h|--help|*)
        usage
        ;;
    esac
    shift
  done

  if [[ ${#services[@]} -eq 0 ]]; then
    echo "[$(date)][Redpill] No services to monitor. Terminating."
    exit
  fi

  interval=${interval:-30}

  echo "[$(date)][Redpill] Starting Redpill."
  echo "[$(date)][Redpill] Monitoring: ${services[@]}"
  echo "[$(date)][Redpill] Interval: $interval"
  if [[ $cleanup_script ]]; then
    echo "[$(date)][Redpill] Cleanup Script: $cleanup_script"
  fi
  echo "[$(date)][Redpill] Sleeping 5 seconds before monitoring start."

  sleep 5 & sleep_pid=$!
  trap "_terminator $sleep_pid $cleanup_script" INT KILL TERM
  wait

  echo "[$(date)][Redpill] Monitoring started."

  while true; do
        for service_name in "${services[@]}"; do
        if [[ "$(supervisorctl status $service_name | awk '{print $2}')" == "FATAL" ]]; then
            echo "[$(date)][Redpill] $service_name has encountered an unrecoverable error. Terminating supervisor."
            if [[ $cleanup_script ]]; then
              cleanup "$cleanup_script"
            fi
            pkill "supervisord"
            exit
        fi
    done

    sleep $interval & sleep_pid=$!
    trap "_terminator $sleep_pid $cleanup_script" SIGINT SIGKILL SIGTERM
    wait
  done

}

main "$@"
