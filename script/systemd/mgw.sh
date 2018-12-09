#!/bin/bash

exit_msg(){
    EXIT_MSG=$1
    echo ${EXIT_MSG}
    exit 0
} 

ROOT_DIR="/opt/mgw"
DEV_CONF_PATH="${ROOT_DIR}/conf/dev.conf"
TAP_NAME=""
TAP_ADDR=""
TUN_NAME=""
PID_FILE="${ROOT_DIR}/mgw.pid"
#read dev.conf
[ ! -f ${DEV_CONF_PATH} ] && exit_msg "${ROOT_DIR}/conf/dev.conf not existed"
source ${DEV_CONF_PATH} 
[ ${TAP_NAME} = "" ] && exit_msg "TAP_NAME is null, please check ${ROOT_DIR}/conf/dev.conf"
[ ${TAP_ADDR} = "" ] && exit_msg "TAP_ADDR is null, please check ${ROOT_DIR}/conf/dev.conf"
[ ${TUN_NAME} = "" ] && exit_msg "TUN_NAME is null, please check ${ROOT_DIR}/conf/dev.conf"

get_status() {
    #0 stopped
    local status=0
    #1 running
    [ -f ${PID_FILE} ] && ps -hp "$(cat ${PID_FILE})" && ${status}=1
    return ${status}
}

start_mgw() {
    #check if mgw is running
    local status
    get_status || status=$?
    [[ ${status} -eq 1 ]] && exit_msg "mgw is running"
   
    #set tap/tun
    ip addr add ${TAP_ADDR} dev ${TAP_NAME} && \
    ip tuntap add dev ${TUN_NAME} mode tun && \
    ifconfig ${TUN_NAME} up && \
    ip rule add iif ${TAP_NAME} tab 100 && \
    ip route add default dev ${TUN_NAME} table 100 && \
    echo 1 > /proc/sys/net/ipv4/ip_forward && \
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter && \
    sysctl -w net.ipv4.conf.default.rp_filter=0 >> /dev/null
    [[ $? -ne 0 ]] && exit_msg "failed at setup tap/tun"
    
    #start mgw
    [ ! -f "${ROOT_DIR}/mgw" ] && exit_msg "${ROOT_DIR}/mgw not existed"
    [ ! -f "${ROOT_DIR}/conf/mgw.conf" ] && exit_msg "${ROOT_DIR}/conf/mgw.conf not existed"
    "${ROOT_DIR}/mgw" "${ROOT_DIR}/conf/mgw.conf" >> /dev/null 2>&1 &
    PID=$!
    echo $PID > $PID_FILE

    #block in front 
    while true; do
        ps -hp ${PID} >> /dev/null
        if [[ $? -ne 0 ]]; then
            stop_mgw
            exit_msg "mgw has stopped"
        fi
        sleep 5
    done
}

check_mgw(){
    get_status
    if [[ $? -eq 1 ]]; then
        exit_msg "mgw is running"
    else
        exit_msg "mgw has stopped"
    fi
}

stop_mgw() {
    [ -f ${PID_FILE} ] && ps -hp $(cat ${PID_FILE}) >> /dev/null && kill -9 $(cat ${PID_FILE})
    #unset tap/tun
    ip addr del ${TAP_ADDR} dev ${TAP_NAME} >> /dev/null 2>&1 
    ip rule del iif ${TAP_NAME} tab 100 >> /dev/null 2>&1 
    ip route del default dev ${TUN_NAME} table 100 >> /dev/null 2>&1 
    sleep 5
    ip tuntap del dev ${TUN_NAME} mode tun >> /dev/null 2>&1 
    exit_msg "mgw has stopped"
}

case "$1" in
    start)
        start_mgw
        ;;
    stop)
        stop_mgw
        ;;
    status)
        check_mgw
        ;;
    *)
        echo "$USAGE"
        exit 3
        ;;
esac
