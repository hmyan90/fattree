from monitor.helper import *
from math import fsum
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument('--input', '-f', dest='files', required=True, help='Input rates')
parser.add_argument('--out', '-o', dest='out', default=None, 
        help="Output png file for the plot.")

args= parser.parse_args()


''' Output of bwm-ng has the following format:
    unix_timestamp;iface_name;bytes_out;bytes_in;bytes_total;packets_out;packets_in;packets_total;errors_out;errors_in
    '''

traffics=['stag_prob_0_2_3_data', 'stag_prob_1_2_3_data', 'stag_prob_2_2_3_data',
        'stag_prob_0_5_3_data','stag_prob_1_5_3_data','stag_prob_2_5_3_data','stride1_data', 
        'stride2_data', 'stride4_data', 'stride8_data', 'random0_data', 'random1_data', 'random2_data', 
        'random0_bij_data', 'random1_bij_data','random2_bij_data', 'random_2_flows_data', 
        'random_3_flows_data', 'random_4_flows_data','hotspot_one_to_one_data']

labels=['stag0(0.2,0.3)', 'stag1(0.2,0.3)', 'stag2(0.2,0.3)', 'stag0(0.5,0.3)',
        'stag1(0.5,0.3)', 'stag2(0.5,0.3)', 'stride1', 'stride2',
        'stride4','stride8','rand0', 'rand1', 'rand2','randbij0',
        'randbij1','randbij2','randx2','randx3','randx4','hotspot']

def get_bisection_bw(input_file, pat_iface):
    pat_iface = re.compile(pat_iface)
    
    data = read_list(input_file)

    rate = {} 
    column = 2
        
    for row in data:
        try:
            ifname = row[1]
        except:
            break

        if ifname not in ['eth0', 'eth1', 'lo']:
            if not rate.has_key(ifname):
                rate[ifname] = []
            
            try:
                rate[ifname].append(float(row[column]) * 8.0 / (1 << 20))
            except:
                break
    vals = []
    for k in rate.keys():
        if pat_iface.match(k): 
            avg_rate = avg(rate[k][10:-10])
            vals.append(avg_rate)
            
    return fsum(vals)

def plot_results(args):

    fbb = 16. * 10  #160 mbps

    num_plot = 2
    num_t = 20

    n_t = num_t/num_plot

    bb = {'dij' : [],'two_level' :  [], 'ecmp' : []}

    sw = '[0-3]_[0-1]_1'
    for t in traffics:
        print "Dijkstra: ", t
        input_file = '%s/fattree-dij/%s/rate.txt' %(args.files, t)
        vals = get_bisection_bw(input_file, sw)
        bb['dij'].append(vals/fbb/2)

    for t in traffics:
        print "ECMP: ", t
        # input_file = args.files + '/fattree-ecmp/%s/rate.txt' % t
        input_file = '%s/fattree-ecmp/%s/rate.txt' % (args.files, t)
        vals = get_bisection_bw(input_file, sw)
        bb['ecmp'].append(vals/fbb/2)

    # sw = '[0-3]h[0-1]h1'
    # for t in traffics:
    #     print "Two_level:", t
    #     # input_file = args.files + '/fattree-ecmp/%s/rate.txt' % t
    #     input_file = '%s/two_level_rate.txt' %args.files
    #     vals = get_bisection_bw(input_file, sw)
    #     bb['two_level'].append(vals/fbb/2)


    # for t in traffics:
    #    print "Hedera:", t
    #    input_file = args.files + '/fattree-hedera/%s/rate.txt' % t
    #    vals = get_bisection_bw(input_file, sw)
    #    bb['hedera'].append(vals/fbb/2)


    ind = np.arange(n_t)
    width = 0.2
    fig = plt.figure(1)
    fig.set_size_inches(18.5,6.5)

    for i in range(num_plot):
        fig.set_size_inches(24,12)

        ax = fig.add_subplot(2,1,i+1)
        ax.yaxis.grid()

        plt.ylim(0.0, 1.0)
        plt.xlim(0,10)
        plt.ylabel('Normalized Average Bisection Bandwidth')
        plt.xticks(ind + 2.5*width, labels[i*n_t:(i+1)*n_t])
    
        # FatTree + two-level
        p1 = plt.bar(ind + 3.5*width, bb['ecmp'][i*n_t:(i+1)*n_t], width=width, color='royalblue')
        #
        # FatTree + Dij
        p2 = plt.bar(ind + 2.5*width, bb['dij'][i*n_t:(i+1)*n_t], width=width, color='green')

        # FatTree + ECMP
        p3 = plt.bar(ind + 1.5*width, bb['ecmp'][i*n_t:(i+1)*n_t], width=width, color='brown')

        plt.legend([p1[0], p2[0], p3[0]],['Dij', 'ECMP','ECMP'],loc='upper left')

        plt.savefig(args.out)


plot_results(args)
