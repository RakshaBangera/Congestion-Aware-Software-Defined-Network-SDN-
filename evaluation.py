#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os, subprocess, shlex, sys
import re
import time
from datetime import datetime

TRACE_PATH = 'traffic/'
MIN_ARBITER_TRAFFIC = 1

#you may change 'current' level for different log details
DBG_LEVEL = {'error': 0,
             'warning':1,
             'overall':2,
             'log':3,
             'info':4,
             'current':4
}


NUM_HOST = 16



#wait for flows complete, change the value in need
#We use 60 sec in our web server
WAIT_TIME = 60

##debug only
SMALL_WAIT = 3

#Differentiate flow sensitivity on ports
LATENCY_SENSITIVE_PORT = [5000,7000]
THROUGHPUT_SENSITIVE_PORT = [5000, 6000]


TRACES=['sample/incast/',
        'sample/perm/',
        'sample/mix/',
        #'hidden1/incast/',
        #'hidden1/perm/',
        #'hidden1/mix/',
        #'hidden2/incast/',
        #'hidden2/perm/',
        #'hidden2/mix/'
]






def cmd(command):
    return os.system(command)

def s_print(level, str):
    if level <= DBG_LEVEL['current']:
        sys.stdout.write(str + '\n')
        

class Descriptor:
    def __init__(self, dirt, nhost):
        self.directory = dirt
        self.traffic = {}
        self.nhost = nhost
        self.Load_traffic()
        
    def Traffic_spec(self, host, hostip):
        traffic = {}
        p = re.compile("-d h(\S*) -p (\S*) -n (\S*)")
        traffic_file = self.directory + host +'.tr'
        for line in open(traffic_file):
            m = p.match(line)
            if m != None:
                dstid = m.group(1)
                dstport = m.group(2)
                vol = m.group(3)
                vol_num = int(re.findall("\d+", vol)[0])
                if 'K' in vol:
                    vol_num *= 1000
                elif 'G' in vol:
                    vol_num *= 1e9
                elif 'M' in vol:
                    vol_num *= 1e6
                traffic[hostip+':'+'10.0.0.'+dstid+':'+dstport] = vol_num
                
        return traffic
        
    def Load_traffic(self):
        for hostid in range(1,self.nhost + 1):
            host = 'h' + str(hostid)
            hostip = '10.0.0.'+str(hostid)
            # retrieve traffic specification
            traffic_ = self.Traffic_spec(host, hostip)
            for item in traffic_:
                if item not in self.traffic:
                    self.traffic[item] = traffic_[item]
                else:
                    self.traffic[item] += traffic_[item]

    def Get_traffic_spec(self):
        return self.traffic
    
class Analyzer:
    def __init__(self, nhost,spec, weight):
        self.weight = weight
        self.starttime = 0
        self.nhost = nhost
        self.arbiter_stat = {}
        self.flow_stat = {}

        self.overall_stat = {'avr_goodput':0,
                             'num_thr_sen_flow':0,
                             'agg_size':0,
                             'tail_FCT':0,
                             'send_incomplete': 0,
                             'recv_incomplete': 0,
                             'flow_complete':0,
                             'use_arbiter':0,

                             'score':0}  #score is tentatively defined
        

        for flow in spec:
            self.flow_stat[flow] = {'status':'NULL',
                                    'size':spec[flow],
                                    'lat_sen':self.Is_latency_sensitive(flow),
                                    'thr_sen':self.Is_throughput_sensitive(flow),
                                    'goodput':0,
                                    'FCT':0,
                                    'send':0,
                                    'send_FCT':0,
                                    'recv':0,
                                    'recv_FCT':0}

    def Is_latency_sensitive(self, flow):
        p = re.compile("(\S*)\:(\S*)\:(\S*)")
        m = p.match(flow)
        if m != None:
            src = m.group(1)
            dst = m.group(2)
            port = int(m.group(3))
            return int(port / 1000) * 1000 in LATENCY_SENSITIVE_PORT
            
    def Is_throughput_sensitive(self, flow):
        p = re.compile("(\S*)\:(\S*)\:(\S*)")
        m = p.match(flow)
        if m != None:
            src = m.group(1)
            dst = m.group(2)
            port = int(m.group(3))
            return int(port / 1000) * 1000 in THROUGHPUT_SENSITIVE_PORT
                
    def Host_name(self, hostid):
        return 'h' + str(hostid)
        
    def Host_ip(self,hostid):
        return '10.0.0.'+str(hostid)
        
    def Read_flow(self, flow):
        src = "NULL"
        dst = "NULL"
        port = "NULL"
        p = re.compile("(\S*)\:(\S*)\:(\S*)")
        m = p.match(flow)
        if m != None:
            src = m.group(1)
            dst = m.group(2)
            port = m.group(3)
        return src,dst,port

    def Analyze_flow(self, src, dst, port, hostid):
        dump_file = 'dump/' + self.Host_name(hostid) + '.pcap'
        command = 'sudo tcpdump vlan and dst ' + dst + ' and src ' + src + ' and dst port ' + port + ' -r ' + dump_file + ' -n -w dump/tmp.pcap > logs/dump-tmp.log 2>&1'
        cmd(command)
            
        command = 'capinfos -Tm dump/tmp.pcap'
        info = os.popen(command).read()
        pos1 = info.find("\n")
        #print info[:pos1]
        pos2 = info.find("\n", pos1+1)
        info_list = info[pos1+1:pos2].split(",")                    
        #print info_list

        #there could be multiple reasons into this outcome
        #1. dump_file does not exists, meaning you fail to capture packets
        #2. the pcap format is wrong
        if (len(info_list) < 7):
            s_print(DBG_LEVEL['error'], 'dump file error in ' + dump_file)
            return 0, 0
        
        pkt = int(info_list[6])
        
        #here we only calculate payload size
        #Ether(14) + Vlantag(4) + IP (20) + UDP(8) = 46 Byte header
        #let us know if this calculation does not work for you
        byt = int(info_list[8]) - pkt * 46  #total bytes
        thr = float(info_list[13])       #bps
        pktrate = float(info_list[15])   #packets/sec
        pktsize = float(info_list[14])   #average packet size
        #print pkt, byt, thr,pktrate, pktsize
        
        
        # the duration in capinfos is not precise
        # instead we use..
        if pkt == 0:
            delay = 0
        else:
            #command = 'tshark -r dump/tmp.pcap -Y "frame.number == 1" -T fields -e frame.time'
            #start = os.popen(command).read()
            command = 'tshark -r dump/tmp.pcap -Y "frame.number == ' + str(pkt) + '\" -T fields -e frame.time'
            end = os.popen(command).read()
            endtime = datetime.strptime(end.split('.')[0] + '.' + end.split('.')[1][0:6],"%b  %d, %Y %H:%M:%S.%f")
            
            delay = (endtime - self.starttime).total_seconds()
            

        return byt, delay
        
    def Arbiter_traffic(self, hostid):
        dump_ctrl = 'dump/' + self.Host_name(hostid) + '-ctrl.pcap'
        command = 'sudo tcpdump \"(port 5000) or (vlan and port 5000)\" -r ' + dump_ctrl + ' -n -w dump/tmp-arbiter.pcap > logs/dump-tmp.log 2>&1'
        cmd(command)
        
        command = 'capinfos -Tm dump/tmp-arbiter.pcap'
        info = os.popen(command).read()
        pos1 = info.find("\n")
        pos2 = info.find("\n", pos1+1)
        info_list = info[pos1+1:pos2].split(",")

        #there could be multiple reasons into this outcome
        #1. dump_file does not exists, meaning you fail to capture packets
        #2. the pcap format is wrong
        if (len(info_list) < 7):
            s_print(DBG_LEVEL['error'], 'dump file error in ' + dump_file)
            self.arbiter_stat[self.Host_name(hostid)] = 0
        else:
            self.arbiter_stat[self.Host_name(hostid)] = int(info_list[6])

    def Eval_traffic(self, hostid):
        for flow in self.flow_stat:
            src,dst,port = self.Read_flow(flow)
            if dst == self.Host_ip(hostid) or src == self.Host_ip(hostid):
                pkt, delay = self.Analyze_flow(src,dst,port,hostid)
                    
                if dst == self.Host_ip(hostid):
                    self.flow_stat[flow]['recv'] = pkt
                    self.flow_stat[flow]['recv_FCT'] = delay
                elif src == self.Host_ip(hostid):
                    self.flow_stat[flow]['send'] = pkt
                    self.flow_stat[flow]['send_FCT'] = delay

    
    def Exam_flow(self):
        for flow in self.flow_stat:
            if self.flow_stat[flow]['send'] < self.flow_stat[flow]['size']:
                self.flow_stat[flow]['status'] = 'Send incomplete'
                self.overall_stat['send_incomplete'] += 1
            elif self.flow_stat[flow]['recv'] < self.flow_stat[flow]['size']:
                self.flow_stat[flow]['status'] = 'Recv incomplete'
                self.overall_stat['recv_incomplete'] += 1
            else:
                self.flow_stat[flow]['status'] = 'Flow complete'
                self.overall_stat['flow_complete'] += 1
                self.flow_stat[flow]['FCT'] = self.flow_stat[flow]['recv_FCT']
                self.flow_stat[flow]['goodput'] = self.flow_stat[flow]['size'] * 8.0 / self.flow_stat[flow]['FCT'] / 1e6

                
                if self.flow_stat[flow]['lat_sen']:
                    self.overall_stat['agg_size'] += self.flow_stat[flow]['size']
                    self.overall_stat['tail_FCT'] = max(self.overall_stat['tail_FCT'], self.flow_stat[flow]['FCT'])
                    
                    
                if self.flow_stat[flow]['thr_sen']:
                    self.overall_stat['num_thr_sen_flow'] += 1
                    self.overall_stat['avr_goodput'] += self.flow_stat[flow]['goodput']


            flowlog = "flow " + flow + '\t' \
                      + "FCT " + str(self.flow_stat[flow]['FCT']) + '\t' \
                      + "goodput " + str( self.flow_stat[flow]['goodput']) +' Mbps\t' \
                      + "expt " + str( self.flow_stat[flow]['size']) + '\t' \
                      + "dump " + str( self.flow_stat[flow]['recv']) + '\t' \
                      + self.flow_stat[flow]['status']

            s_print(DBG_LEVEL['log'], flowlog)

        if self.overall_stat['num_thr_sen_flow'] != 0:
            self.overall_stat['avr_goodput'] = self.overall_stat['avr_goodput'] / self.overall_stat['num_thr_sen_flow']

        if self.overall_stat['tail_FCT'] != 0:
            self.overall_stat['score'] = (self.overall_stat['avr_goodput'] + self.overall_stat['agg_size'] * 8.0 / 1e6 / self.overall_stat['tail_FCT']) * self.weight
        
    def Exam_arbiter(self):
        for host in self.arbiter_stat:
            if self.arbiter_stat[host] >= MIN_ARBITER_TRAFFIC:
                self.overall_stat['use_arbiter'] += 1
                s_print(DBG_LEVEL['log'], host+" to arbiter traffic: "+ str(self.arbiter_stat[host]))
                

    def Display(self):
        s_print(DBG_LEVEL['overall'],"hosts used arbiter: "+str( self.overall_stat['use_arbiter']))
        s_print(DBG_LEVEL['overall'], "incomplete send: "+str( self.overall_stat['send_incomplete']))
        s_print(DBG_LEVEL['overall'],"incomplete receive: "+str(self.overall_stat['recv_incomplete']))
        s_print(DBG_LEVEL['overall'],"correct flows: "+ str(self.overall_stat['flow_complete']))
        s_print(DBG_LEVEL['overall'], "total flows: " + str(len(self.flow_stat)))
        s_print(DBG_LEVEL['overall'],"ave throughput: "+str(self.overall_stat['avr_goodput']))
        s_print(DBG_LEVEL['overall'], "tail FCT: "+str(self.overall_stat['tail_FCT']))
        s_print(DBG_LEVEL['overall'],"score: "+str(self.overall_stat['score']))
    

        
    def Do_analysis(self, starttime):
        #accumulate flow statistics from dump files
        t1 = time.time()
        self.starttime = starttime
        sys.stdout.write("Analyzing dumps for host: ")
        for hostid in range(1, self.nhost+1):
            sys.stdout.write("%s " % (self.Host_name(hostid)))
            sys.stdout.flush()
            self.Arbiter_traffic(hostid)
            self.Eval_traffic(hostid)
        sys.stdout.write("\n")
        
        #examinate if all our  goals are achieved
        s_print(DBG_LEVEL['overall'], "Examinating flows...")
        self.Exam_flow()
        self.Exam_arbiter()
        s_print(DBG_LEVEL['overall'], "Analysis time: "+str(time.time()-t1))

        self.Display()
        
        return self.overall_stat

        


class Experimenter:
    def __init__(self, trace, nhost):
        self.trace_path = trace
        self.nhost = nhost
        if 'perm' in trace:
            self.weight = 1.0 / 15
        else:
            self.weight = 1.0

        self.descriptor = Descriptor(self.trace_path, self.nhost)
        self.analyzer = Analyzer(self.nhost, self.descriptor.Get_traffic_spec(), self.weight)
        self.start_time = 0
        
        if not os.path.exists("dump"):
            os.makedirs("dump")
        if not os.path.exists("logs"):
            os.makedirs("logs")

    def Cleanup(self):
        cmd("rm -rf dump/* > /dev/null 2>&1")
        cmd("rm -rf logs/* > /dev/null 2>&1")       

    def Killtask(self):
        cmd("sudo killall tcpdump > /dev/null 2>&1")
        #do not want to kill your arbiter_network.py
        cmd("sudo pkill -9 -x arbiter > /dev/null 2>&1") 
        cmd("sudo killall -9 cperf > /dev/null 2>&1")
        time.sleep(SMALL_WAIT)
        
    def Dump_start(self):
        for hostid in range(1,self.nhost+1):
            host = 'h' + str(hostid)
            command = '~/mininet/util/m ' + host + ' sudo tcpdump -i ' + host +'-eth0' + ' -n -s 64 -B 8192 -w dump/' + host + '.pcap > logs/dump-' + host + '.log 2>&1 &'
            
            s_print(DBG_LEVEL['info'], command)
            cmd(command)
            command = '~/mininet/util/m ' + host + ' sudo tcpdump -i ' + host +'-eth1' + ' -n -s 64 -B 8192 -w dump/' + host + '-ctrl.pcap > logs/dump-' + host + '-ctrl.log 2>&1 &'
            s_print(DBG_LEVEL['info'], command)
            cmd(command)
        time.sleep(SMALL_WAIT)

    def Arbiter_start(self):
        cmd("./arbiter >logs/arbiter.log 2>&1 &")
        time.sleep(SMALL_WAIT)

    def Traffic_start(self):
        for hostid in range(1,self.nhost+1):
            host = 'h' + str(hostid)
            command = '~/mininet/util/m ' + host + ' ./cperf ' + self.trace_path + host + '.tr > logs/cperf-' + host +'.log 2>&1 &'
            s_print(DBG_LEVEL['info'],command)
            cmd(command)
        time.sleep(SMALL_WAIT)
    
    def Execute(self):
        s_print(DBG_LEVEL['overall'], "Clear existing task...")
        self.Killtask()
        self.Cleanup()
        
        s_print(DBG_LEVEL['overall'],"Starting Arbiter...")
        self.Arbiter_start()

        s_print(DBG_LEVEL['overall'],"Starting tcpdump...")
        self.Dump_start()
        
        self.start_time = datetime.now()
        
        s_print(DBG_LEVEL['overall'],"Starting traffic...")
        self.Traffic_start()
        

        s_print(DBG_LEVEL['overall'],"wait "+str(WAIT_TIME)+" sec for all flows finished...")
        time.sleep(WAIT_TIME)

        s_print(DBG_LEVEL['overall'], "Terminating all task...")
        self.Killtask()
    
        s_print(DBG_LEVEL['overall'], "Analyzing traffic statistics...")
        return self.analyzer.Do_analysis(self.start_time)

    
if __name__=='__main__':
    total_result = {}
    for trace in TRACES:
        s_print(DBG_LEVEL['overall'], "Evaluating : " + trace)
        experimenter = Experimenter( TRACE_PATH + trace, NUM_HOST)
        result = experimenter.Execute()

        #we may change the definition for overall results
        for key in result:
            if key not in total_result:
                total_result[key] = 0
            total_result[key] += result[key]

    #you have the risk of getting 0 score if some flows are incorrect
    total_flow = total_result['recv_incomplete'] + total_result['send_incomplete'] + total_result['flow_complete']
    if total_flow != total_result['flow_complete'] or total_result['use_arbiter'] < 94:
        total_result['avr_goodput'] = 0
        total_result['tail_FCT'] = 0
        total_result['score'] = 0
        
    s_print(DBG_LEVEL['overall'], "=== Overall result ===")
    s_print(DBG_LEVEL['overall'],"hosts used arbiter: "+str(total_result['use_arbiter']))
    s_print(DBG_LEVEL['overall'], "incomplete send: "+str(total_result['send_incomplete']))
    s_print(DBG_LEVEL['overall'],"incomplete receive: "+str(total_result['recv_incomplete']))
    s_print(DBG_LEVEL['overall'],"correct flows: "+ str(total_result['flow_complete']))
    s_print(DBG_LEVEL['overall'], "total flows: " + str(total_flow))
    s_print(DBG_LEVEL['overall'],"ave throughput: "+str(total_result['avr_goodput']))
    s_print(DBG_LEVEL['overall'], "tail FCT: "+str(total_result['tail_FCT']))
    s_print(DBG_LEVEL['overall'],"score: "+str(total_result['score']))


        
