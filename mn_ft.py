'''
based on riplpox 
'''

import sys
sys.path.append(".")

from mininet.topo import Topo
from mininet.node import Controller, RemoteController, OVSKernelSwitch, CPULimitedHost
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.util import custom
from mininet.log import setLogLevel, info, warn, error, debug


from DCTopo import FatTreeTopo

from subprocess import Popen, PIPE
from argparse import ArgumentParser
import multiprocessing
from time import sleep
from monitor.monitor import monitor_devs_ng
import os


# Number of pods in Fat-Tree 
K = 4

# Queue Size
QUEUE_SIZE = 100

# Link capacity (Mbps)
BW = 10 

parser = ArgumentParser(description="mininet_fattree")

parser.add_argument('-d', '--dir', dest='output_dir', default='log',
        help='Output directory')

parser.add_argument('-i', '--input', dest='input_file',
        default='inputs/all_to_all_data',
        help='Traffic generator input file')

parser.add_argument('-t', '--time', dest='time', type=int, default=30,
        help='Duration (sec) to run the experiment')

parser.add_argument('-p', '--cpu', dest='cpu', type=float, default=-1,
        help='cpu fraction to allocate to each host')

parser.add_argument('--iperf', dest='iperf', default=False, action='store_true',
        help='Use iperf to generate traffics')

parser.add_argument('--ecmp',dest='ECMP',default=False,
        action='store_true',help='Run the experiment with ECMP routing')

parser.add_argument('--tlr',dest='tlr', default=False,
        action='store_true', help='Run the experiment with Fat-Tree two-level routing')

parser.add_argument('--dijkstra',dest='dij',default=False,
        action='store_true',help='Run the experiment with dijkstra routing')

args = parser.parse_args()



def FatTreeNet(args, k=4, bw=10, cpu=-1, queue=100, controller='DCController'):
    ''' Create a Fat-Tree network '''

    if args.ECMP:
        pox_c = Popen("~/pox/pox.py %s --topo=ft,4 --routing=ECMP > log/pox.log" %controller, shell=True)
    elif args.dij:
        pox_c = Popen("~/pox/pox.py %s --topo=ft,4 --routing=dij" %controller, shell=True)
    else:
        info('**error** the routing scheme should be ecmp or dijkstra\n')

    sleep(2)
    info('*** Creating the topology\n')
    topo = FatTreeTopo(k)

    host = custom(CPULimitedHost, cpu=cpu)
    link = custom(TCLink, bw=bw, max_queue_size=queue)
    
    net = Mininet(topo, host=host, link=link, switch=OVSKernelSwitch,
            controller=RemoteController)

    return net

"""
def start_tcpprobe():
    ''' Install tcp_probe module and dump to file '''
    os.system("rmmod tcp_probe; modprobe tcp_probe full=1;")
    Popen("cat /proc/net/tcpprobe > %s/tcp.txt" %args.output_dir ,shell=True)


def stop_tcpprobe():
    os.system("killall -9 cat")
"""

def _gen_routing_mode_str(args):

    if args.ECMP:
        return "ECMP"
    elif args.dij:
        return "dij"
    else:
        return 'two_level'

def wait_listening(client, server, port):
  "Wait until server is listening on port"
  if not 'telnet' in client.cmd('which telnet'):
    raise Exception('Could not find telnet')
  cmd = ('sh -c "echo A | telnet -e A %s %s"' %
         (server.IP(), port))
  while 'Connected' not in client.cmd(cmd):
    print('waiting for', server,
           'to listen on port', port, '\n')
    sleep(.5)

def iperfTrafficGen(args, hosts, net):
    ''' Generate traffic pattern using iperf and monitor all of thr interfaces

    input format:
    src_ip dst_ip dst_port type seed start_time stop_time flow_size r/e
    repetitions time_between_flows r/e (rpc_delay r/e)

    '''

    host_list = {}
    for h in hosts:
        host_list[h.IP()] = h

    port = 5001
    data = open(args.input_file)
    datas = []
    for line in data:
        flow = line.split(' ')
        if flow[0] not in host_list or flow[1] not in host_list:
            print '%s, %s not in host list' %(flow[0], flow[1])
            continue
        datas.append([flow[0], flow[1]])

    start_tcpprobe()

    info('*** Starting iperf ...\n')

    dst_ips = set()
    for data in datas:
        dst_ips.add(data[1])

    for dst_ip in dst_ips:

        dst = host_list[dst_ip]
        aa = 'mnexec -a %s iperf -s -p %s > /dev/null &' % (dst.pid, port)
        Popen(aa, shell=True)

    monitor = multiprocessing.Process(target=monitor_devs_ng, args=
    ('%s/%s_rate.txt' % (args.output_dir, _gen_routing_mode_str(args)), 0.01))

    monitor.start()

    # Start the senders
    for data in datas:
        src = host_list[data[0]]
        dst = host_list[data[1]]
        aa='mnexec -a %s iperf -c %s -p %s -t %d -i 1 -yc > /dev/null &' % (src.pid, dst.IP(), port, args.time)
        Popen(aa, shell=True)

    # for line in data:
    #     flow = line.split(' ')
    #     src_ip = flow[0]
    #     dst_ip = flow[1]
    #     print src_ip, dst_ip
    #     if src_ip not in host_list:
    #         continue
    #     sleep(0.2)
    #     server = host_list[dst_ip]
        # iperf_s = 'iperf -s -p %s > %s/server.txt' % (port, args.output_dir)
        # iperf_s = 'iperf -s -p %d' % (port)
        # print iperf_s
        # cmd_s = 'mnexec -a %s %s' %(server.pid, iperf_s)
        # server.popen(iperf_s, shell=True)
        # print cmd_s
        # Popen(cmd_s, shell=True)
        # server.popen('iperf -s -p %s > log/server.txt' % port, shell=True)
        # server.popen('ifconfig > log/server.txt')
        # server.popen('iperf -s -p %s > ~/hedera/server.txt' % port, shell=True)
        # server.cmd('iperf -s -p %d' % port)

        # client = host_list[src_ip]

        # iperf_c = 'iperf -c %s -p %s -t %d > %s/client.txt' % (server.IP(), port, args.time, args.output_dir)
        # iperf_c = 'iperf -c %s -p %d -t %d' % (server.IP(), port, args.time)
        # print iperf_c
        # client.popen(iperf_c, shell=True)
        # cmd_c = 'mnexec -a %s %s' % (client.pid, iperf_c)
        # print cmd_c
        # Popen(cmd_c, shell=True)
        # client.popen('iperf -c %s -p %s -t %d > log/client.txt'
        #              % (server.IP(), port, args.time), shell=True)
        # client.popen('iperf -c %s -p %s -t %d > ~/hedera/client.txt'
        #              % (server.IP(), port, args.time), shell=True)
        # client.cmd('iperf -c %s -p %s -t %d' % (server.IP(), port, args.time))

    sleep(args.time)

    monitor.terminate()

    info('*** stoping iperf ...\n')
    stop_tcpprobe()

    Popen("killall -9 iperf", shell=True).wait()


def FatTreeTest(args,controller):
    net = FatTreeNet(args, k=K, cpu=args.cpu, bw=BW, queue=QUEUE_SIZE,
            controller=controller)
    net.start()
    '''
    uncomment and implement the following fucntion if flow tables are installed proactively, 
    in this mode, the mininet can work without a controller
    '''

    # install_proactive(topo)

    # wait for the switches to connect to the controller
    info('** Waiting for switches to connect to the controller\n')
    sleep(5)

    info('** Start iperf test\n**')
    hosts = net.hosts
    
    iperfTrafficGen(args, hosts, net)

    net.stop()

def clean():
    ''' Clean any the running instances of POX '''

    p = Popen("ps aux | grep 'pox' | awk '{print $2}'",
            stdout=PIPE, shell=True)
    p.wait()
    procs = (p.communicate()[0]).split('\n')
    for pid in procs:
        try:
            pid = int(pid)
            Popen('kill %d' % pid, shell=True).wait()
        except:
            pass

if __name__ == '__main__':

    setLogLevel( 'info' )
    if not os.path.exists(args.output_dir):
        print args.output_dir
        os.makedirs(args.output_dir)

    clean()

    if args.ECMP:
        FatTreeTest(args,controller='DCController')
    elif args.dij:
        FatTreeTest(args,controller='DCController')
    elif args.tlr:
        #flow tables in two-level routing are installed proactively, so no need of controller
        FatTreeTest(args,controller= None) 
    else:
        info('******error**** please specify either ecmp, dijkstra or tlr\n')
        
    clean()

    Popen("killall -9 top bwm-ng", shell=True).wait()
    os.system('sudo mn -c')
