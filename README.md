# IP复用文档
* 依赖
    * MESA_framework
        * .so放在/opt/MESA/lib下
        * .h放在/opt/MESA/include下
        * 设置环境变量
            * 执行update_env.sh
                * echo $LD_LIBRARY_PATH，查看其是否包含/opt/MESA/lib
            * 没有update_env.sh
                * 在~/.bash_profile添加 export LIBRARY_PATH=/opt/MESA/lib/:$LIBRARY_PATH
                * source ~/.bash_profile
    * 关闭防火墙
* 安装
    * rpm -ivh mgw-1.0.0-1.el7.centos.x86_64.rpm
* 卸载
    * systemctl stop mgw
    * rpm -e mgw-1.0.0-1.el7.centos.x86_64.rpm
* 配置项
    * dev.conf
        * TAP_NAME: TAP设备的名称，和softether server中虚拟hub桥接设备的TAP设备名字一样。默认为tap_softether
        * TAP_ADDR: TAP设备的地址，和softether server中虚拟hub的secureNAT的默认网关一致，默认为192.168.30.254/24
    * mgw.conf
        * [global]
            * log_level: 默认30(FATAL)
            * access_id: 接入服务器id, 目前为0即可
        * [Maat_snat_policy]
            * Maat_redis_ip: IR_SNAT_POLICY表所在的redis的ip 
            * Maat_redis_port: IR_SNAT_POLICY表所在的redis的port
            * Maat_redis_index: IR_SNAT_POLICY表所在的redis的index
        * [Maat_dnat_policy]
            * Maat_redis_ip: IR_DNAT_POLICY表所在的redis的ip 
            * Maat_redis_port: IR_DNAT_POLICY表所在的redis的port
            * Maat_redis_index: IR_DNAT_POLICY表所在的redis的index
        * [Maat_snat_cand_ip]
            * Maat_redis_ip: IR_CANDIDATE_IP表所在的redis的ip 
            * Maat_redis_port: IR_CANDIDATE_IP表所在的redis的port
            * Maat_redis_index: IR_CANDIDATE_IP表所在的redis的index
        * [Maat_mrl_ip]
            * Maat_redis_ip: 表所在的redis的ip 
            * Maat_redis_port: IR_MRL_IP_INFO表所在的redis的port
            * Maat_redis_index: IR_MRL_IP_INFO表所在的redis的index
        * [field_stat]
            * stat_path: 性能监控文件路径，默认即可
        * [vpn_server]
            * vpn_server_ip: 目前为localhost
            * vpn_server_port: 默认为443
            * vpn_server_passwd: 默认111111
            * hub_list: hub列表
                * 一个{}内表示一个hub，不同的{}之间用英文逗号隔开
                * 一个{}内有4项，用空格分开, 分别为hub名称，hub密码，hub的dhcp分配的ip范围
            * polling_interval: vpn_monitor线程轮询间隔，默认为30s
        * [mrl]
            * default_ip: mrl服务器ip
            * port: mrl服务器的端口
        * [udp_server]
            * ip: 和mrl通信监听的ip,默认为本机ip
            * port: 默认为33456
        * 剩下的各种hash表按照需要修改，一般默认即可
* 启动/终止
    * systemctl start/status/stop mgw
* 日志查看
    * mgw日志
        * /opt/mgw/log下
    * systemd日志
        * journalctl -u mgw.service
* 性能监控
    * watch -d cat /opt/mgw/fs2_mgw.status
* 常见问题
    * vpn连不上
        * 检查vpn用户名，密码是否正确
    * tap_softether网卡上捕不到包
        * vpn server中的secureNAT的配置中默认网关和默认dns是否改成192.168.30.254
        * 检查tap_softether有没有绑定ip地址192.168.30.254/24。**需要加上掩码**
    * tap_softether捕到包，tun_mgw上捕不到包
        * 检查防火墙是否关闭，如果没有，关闭防火墙
    * mgw不停重启
        * 这种情况通常mgw.service的启动失败
        * 解决方法:
            * systemctl stop mgw
            * journalctl -u mgw.service看下systemd日志
            * sh /opt/mgw/script/systemd/mgw.sh start手动执行脚本看看具体是哪里失败
    * 包发送给mrl，没有收到回复，最可能的原因是复用的ip没有联网。




