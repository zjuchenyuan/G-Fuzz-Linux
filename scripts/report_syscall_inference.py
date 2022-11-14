import sys, os, re
FOLDER = os.path.abspath(os.path.dirname(__file__))
text = open(sys.argv[1]).read()
#trace = text.split("Call Trace:")[1].split("RIP: ")[0]
res = set()
folders2syscalls = {
    #Gfuzz network ipv4/ipv6 inference rules
    "net/ipv4": ['syz_emit_ethernet$ipv4'],
    "net/ipv6": ['syz_emit_ethernet$ipv6'],
    "net/ipv4/tcp": ['syz_emit_ethernet$ipv4_tcp'],
    "net/ipv4/udp": ['syz_emit_ethernet$ipv4_udp'],
    "net/ipv6/tcp": ['syz_emit_ethernet$ipv6_tcp'],
    "net/ipv6/udp": ['syz_emit_ethernet$ipv6_udp'],
    "net/ipv4/icmp.c": ['syz_emit_ethernet$ipv4_icmp'],
    "net/ipv6/icmp.c": ['syz_emit_ethernet$ipv6_icmp'],
    "net/ipv4/igmp.c": ['syz_emit_ethernet$ipv4_igmp'],
    # more Linux network rules
    "net/wireless/80211.c": ['sendmsg$NL80211_CMD_SET_NOACK_MAP', 'sendmsg$NL80211_CMD_DISASSOCIATE', 'sendmsg$NL80211_CMD_SET_CQM', 'sendmsg$NL80211_CMD_NEW_KEY', 'sendmsg$NL80211_CMD_REGISTER_BEACONS', 'sendmsg$NL80211_CMD_SET_BEACON', 'sendmsg$NL80211_CMD_RADAR_DETECT', 'sendmsg$NL80211_CMD_CHANNEL_SWITCH', 'sendmsg$NL80211_CMD_GET_MPP', 'sendmsg$NL80211_CMD_STOP_AP', 'sendmsg$NL80211_CMD_STOP_NAN', 'sendmsg$NL80211_CMD_RELOAD_REGDB', 'sendmsg$NL80211_CMD_SET_REKEY_OFFLOAD', 'sendmsg$NL80211_CMD_START_AP', 'sendmsg$NL80211_CMD_GET_COALESCE', 'sendmsg$NL80211_CMD_ADD_TX_TS', 'sendmsg$NL80211_CMD_SET_POWER_SAVE', 'syz_genetlink_get_family_id$nl80211', 'sendmsg$NL80211_CMD_NOTIFY_RADAR', 'sendmsg$NL80211_CMD_TRIGGER_SCAN', 'ioctl$sock_SIOCGIFINDEX_80211', 'sendmsg$NL80211_CMD_CONNECT', 'sendmsg$NL80211_CMD_SET_MPATH', 'sendmsg$NL80211_CMD_SET_INTERFACE', 'sendmsg$NL80211_CMD_GET_MPATH', 'sendmsg$NL80211_CMD_SET_PMK', 'sendmsg$NL80211_CMD_STOP_P2P_DEVICE', 'sendmsg$NL80211_CMD_SET_WIPHY_NETNS', 'sendmsg$NL80211_CMD_SET_WIPHY', 'sendmsg$NL80211_CMD_ASSOCIATE', 'sendmsg$NL80211_CMD_STOP_SCHED_SCAN', 'sendmsg$NL80211_CMD_SET_CHANNEL', 'sendmsg$NL80211_CMD_PROBE_MESH_LINK', 'sendmsg$NL80211_CMD_SET_WOWLAN', 'sendmsg$NL80211_CMD_UPDATE_CONNECT_PARAMS', 'sendmsg$NL80211_CMD_NEW_STATION', 'sendmsg$NL80211_CMD_NEW_INTERFACE', 'sendmsg$NL80211_CMD_DEL_KEY', 'sendmsg$NL80211_CMD_DEL_PMK', 'sendmsg$NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL', 'sendmsg$NL80211_CMD_ADD_NAN_FUNCTION', 'sendmsg$NL80211_CMD_UNEXPECTED_FRAME', 'sendmsg$NL80211_CMD_GET_SURVEY', 'sendmsg$NL80211_CMD_SET_TX_BITRATE_MASK', 'sendmsg$NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH', 'sendmsg$NL80211_CMD_JOIN_OCB', 'sendmsg$NL80211_CMD_FRAME', 'sendmsg$NL80211_CMD_DEAUTHENTICATE', 'sendmsg$NL80211_CMD_ABORT_SCAN', 'sendmsg$NL80211_CMD_SET_KEY', 'sendmsg$NL80211_CMD_REMAIN_ON_CHANNEL', 'sendmsg$NL80211_CMD_GET_PROTOCOL_FEATURES', 'sendmsg$NL80211_CMD_START_SCHED_SCAN', 'sendmsg$NL80211_CMD_DEL_TX_TS', 'sendmsg$NL80211_CMD_UPDATE_OWE_INFO', 'sendmsg$NL80211_CMD_SET_PMKSA', 'sendmsg$NL80211_CMD_LEAVE_IBSS', 'sendmsg$NL80211_CMD_UPDATE_FT_IES', 'sendmsg$NL80211_CMD_REGISTER_FRAME', 'sendmsg$NL80211_CMD_TDLS_CHANNEL_SWITCH', 'sendmsg$NL80211_CMD_GET_FTM_RESPONDER_STATS', 'sendmsg$NL80211_CMD_DISCONNECT', 'sendmsg$NL80211_CMD_GET_WIPHY', 'sendmsg$NL80211_CMD_SET_MCAST_RATE', 'sendmsg$NL80211_CMD_SET_BSS', 'syz_80211_inject_frame', 'sendmsg$NL80211_CMD_JOIN_MESH', 'sendmsg$NL80211_CMD_CHANGE_NAN_CONFIG', 'sendmsg$NL80211_CMD_DEL_INTERFACE', 'syz_80211_join_ibss', 'sendmsg$NL80211_CMD_TDLS_MGMT', 'sendmsg$NL80211_CMD_SET_TID_CONFIG', 'sendmsg$NL80211_CMD_SET_MULTICAST_TO_UNICAST', 'sendmsg$NL80211_CMD_CRIT_PROTOCOL_START', 'sendmsg$NL80211_CMD_GET_WOWLAN', 'sendmsg$NL80211_CMD_CRIT_PROTOCOL_STOP', 'sendmsg$NL80211_CMD_DEL_NAN_FUNCTION', 'sendmsg$NL80211_CMD_TDLS_OPER', 'sendmsg$NL80211_CMD_GET_SCAN', 'sendmsg$NL80211_CMD_FLUSH_PMKSA', 'sendmsg$NL80211_CMD_LEAVE_OCB', 'sendmsg$NL80211_CMD_JOIN_IBSS', 'sendmsg$NL80211_CMD_START_P2P_DEVICE', 'sendmsg$NL80211_CMD_GET_INTERFACE', 'sendmsg$NL80211_CMD_GET_STATION', 'sendmsg$NL80211_CMD_GET_POWER_SAVE', 'sendmsg$NL80211_CMD_DEL_MPATH', 'sendmsg$NL80211_CMD_NEW_MPATH', 'sendmsg$NL80211_CMD_SET_MAC_ACL', 'sendmsg$NL80211_CMD_AUTHENTICATE', 'sendmsg$NL80211_CMD_GET_KEY', 'sendmsg$NL80211_CMD_DEL_STATION', 'sendmsg$NL80211_CMD_LEAVE_MESH', 'sendmsg$NL80211_CMD_PROBE_CLIENT', 'sendmsg$NL80211_CMD_START_NAN', 'sendmsg$NL80211_CMD_EXTERNAL_AUTH', 'sendmsg$NL80211_CMD_SET_COALESCE', 'sendmsg$NL80211_CMD_VENDOR', 'sendmsg$NL80211_CMD_SET_MESH_CONFIG', 'sendmsg$NL80211_CMD_SET_STATION', 'sendmsg$NL80211_CMD_PEER_MEASUREMENT_START', 'sendmsg$NL80211_CMD_SET_QOS_MAP', 'sendmsg$NL80211_CMD_SET_WDS_PEER', 'sendmsg$NL80211_CMD_TESTMODE', 'sendmsg$NL80211_CMD_CONTROL_PORT_FRAME', 'sendmsg$NL80211_CMD_DEL_PMKSA', 'sendmsg$NL80211_CMD_FRAME_WAIT_CANCEL', 'sendmsg$NL80211_CMD_SET_REG', 'sendmsg$NL80211_CMD_GET_REG', 'sendmsg$NL80211_CMD_REQ_SET_REG', 'sendmsg$NL80211_CMD_GET_MESH_CONFIG'],
    "net/can/raw.c": ['getsockopt$CAN_RAW_JOIN_FILTERS', 'setsockopt$CAN_RAW_FD_FRAMES', 'getsockopt$CAN_RAW_FD_FRAMES', 'sendmsg$can_raw', 'getsockopt$CAN_RAW_FILTER', 'setsockopt$CAN_RAW_LOOPBACK', 'setsockopt$CAN_RAW_RECV_OWN_MSGS', 'bind$can_raw', 'socket$can_raw', 'recvmsg$can_raw', 'setsockopt$CAN_RAW_FILTER', 'getsockopt$CAN_RAW_RECV_OWN_MSGS', 'setsockopt$CAN_RAW_JOIN_FILTERS', 'getsockopt$CAN_RAW_LOOPBACK', 'setsockopt$CAN_RAW_ERR_FILTER'],
    "net/bluetooth/l2cap": ['setsockopt$bt_l2cap_L2CAP_CONNINFO', 'getsockopt$bt_l2cap_L2CAP_LM', 'getsockopt$bt_l2cap_L2CAP_CONNINFO', 'syz_init_net_socket$bt_l2cap', 'connect$bt_l2cap', 'setsockopt$bt_l2cap_L2CAP_OPTIONS', 'getsockopt$bt_l2cap_L2CAP_OPTIONS', 'bind$bt_l2cap', 'setsockopt$bt_l2cap_L2CAP_LM', 'accept4$bt_l2cap'],
    # more Linux drivers rules
    "drivers/bluetooth": ['syz_init_net_socket$bt_hci', 'ioctl$sock_bt_hci', 'write$bt_hci', 'bind$bt_hci', 'getsockopt$bt_hci', 'syz_emit_vhci', 'setsockopt$bt_hci_HCI_FILTER', 'setsockopt$bt_hci_HCI_DATA_DIR', 'setsockopt$bt_hci_HCI_TIME_STAMP'],
    "drivers/tty": ["syz_open_dev$tty20", "syz_open_dev$tty1", "syz_open_dev$ttys"],
    "drivers/video/fbdev":['ioctl$FBIOGET_CON2FBMAP', 'ioctl$FBIOGETCMAP', 'openat$fb0', 'ioctl$FBIO_WAITFORVSYNC', 'write$fb', 'mmap$fb', 'ioctl$FBIOGET_VSCREENINFO', 'ioctl$FBIOBLANK', 'ioctl$FBIOPUT_CON2FBMAP', 'ioctl$FBIOGET_FSCREENINFO', 'ioctl$FBIOPUT_VSCREENINFO', 'read$fb', 'ioctl$FBIOPUTCMAP', 'ioctl$FBIOPAN_DISPLAY'],
    # more Linux filesystem rules
    "fs/f2fs": ['ioctl$F2FS_IOC_GET_COMPRESS_BLOCKS', 'ioctl$F2FS_IOC_GET_FEATURES', 'syz_mount_image$f2fs', 'ioctl$F2FS_IOC_RESERVE_COMPRESS_BLOCKS', 'ioctl$F2FS_IOC_PRECACHE_EXTENTS', 'ioctl$F2FS_IOC_GARBAGE_COLLECT', 'ioctl$F2FS_IOC_FLUSH_DEVICE', 'ioctl$F2FS_IOC_START_VOLATILE_WRITE', 'ioctl$F2FS_IOC_ABORT_VOLATILE_WRITE', 'ioctl$F2FS_IOC_GARBAGE_COLLECT_RANGE', 'ioctl$F2FS_IOC_COMMIT_ATOMIC_WRITE', 'ioctl$F2FS_IOC_START_ATOMIC_WRITE', 'ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE', 'ioctl$F2FS_IOC_MOVE_RANGE', 'ioctl$F2FS_IOC_DEFRAGMENT', 'ioctl$F2FS_IOC_WRITE_CHECKPOINT', 'ioctl$F2FS_IOC_RELEASE_COMPRESS_BLOCKS', 'ioctl$F2FS_IOC_SET_PIN_FILE', 'ioctl$F2FS_IOC_GET_PIN_FILE', 'ioctl$F2FS_IOC_RESIZE_FS'],
}
ioctl_constants = {}
enabledsyscalls=[]
for line in open(f"{FOLDER}/enabledsyscalls.txt"):
    s=line.split()[2]
    enabledsyscalls.append(s)
    if s.startswith("syz_mount_image$"): #GFuzz filesystem inference rule
        folder = "fs/"+s.split("syz_mount_image$")[1]
        folders2syscalls.setdefault(folder, []).append(s)
    elif s.startswith("ioctl$"): #GFuzz ioctl constant inference rule
        ioctl_constants[s.split("ioctl$")[1].lower()] = s
for line in text.split("\n"):
    l = line.replace("[inline]","").strip().split()
    if len(l)!=2 or ".c" not in l[1]:
        continue
    func = l[0].split("+")[0]
    filepath = l[1].split(":")[0]
    if os.getenv("DEBUG"):
        print(func, filepath)
    if func.startswith("__x64_sys_"):
        res.add(func.replace("__x64_sys_", ""))
    elif func.startswith("__sys_"):
        res.add(func.replace("__sys_", ""))
    for k, v in folders2syscalls.items():
        if filepath.startswith(k):
            res.update(v)
    if func in ioctl_constants:
        print("ioctl func:", func)
        res.add(ioctl_constants[func])
    words = re.split(r'/|_|-|\.', filepath)
    if "bpf" in words or "seccomp" in words: #GFuzz seccomp/bpf rule
        res.update(["prctl$PR_SET_SECCOMP", "seccomp$SECCOMP_SET_MODE_FILTER", "seccomp$SECCOMP_SET_MODE_FILTER_LISTENER"])
print(sorted(res))