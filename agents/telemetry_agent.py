import client
import os
import time
import json
import argparse
import sys
# import threading
# from multiprocessing import Process
# import subprocess

from scapy.all import sniff
from scapy.all import Packet
from scapy.all import UDP
from scapy.all import XByteField, ShortField, BitField, PacketListField
from scapy.all import bind_layers

parser = argparse.ArgumentParser(description='receive telmetry reports and store them in influxdb')
parser.add_argument('-if','--interface', help='interface to receive on',
                    type=str, action="store", default='veth0')
parser.add_argument('-p','--port', help='port to listen to',
                    type=int, action="store", default='35000')
args = parser.parse_args()

class INT_MD(Packet):
    name = 'INT_MD'
    fields_desc = [
        BitField(name='flow_id', default=0, size=16),
        BitField(name='delay', default=0, size=64),
        BitField(name='jitter', default=0, size=64)
    ]
    def extract_padding(self, s):
        return '', s 
    

class INT_AGG(Packet):
    name = "Aggregated Reports"
    fields_desc = [
        PacketListField('aggregated_reports', None, INT_MD, count_from= lambda x: 16)
    ]

t0 = 0

glb_del_array = {'11': [], '12': [], '13': [], '21': [], '22': [], '23': []}
glb_jit_array = {'11': [], '12': [], '13': [], '21': [], '22': [], '23': []}

glb_num_total_packets = 0




def handle_flow_data(del_array, jit_array):
    global glb_jit_array, glb_del_array
    glb_del_array = {'11': [], '12': [], '13': [], '21': [], '22': [], '23': []}
    glb_jit_array = {'11': [], '12': [], '13': [], '21': [], '22': [], '23': []}
    flow_data = {}
    traffic_info = {}
    path_info = {'11' : 0, '12' : 0, '13' : 0, '21' : 0, '22' : 0, '23' : 0}
    
    # print('del_array', del_array)
    for key in del_array.keys():
        # print('del_array[key]', del_array[key])
        if ( len(del_array[key]) == 0):
            continue
        # print('key', key)

        flow_id = '{}'.format(int(key)//10)
        subflow_id = '{}'.format(int(key)%10 )

        print('flow_id', flow_id,'subflow_id', subflow_id)

        if 'f{}'.format(flow_id) in flow_data.keys():
            flow_data['f{}'.format(flow_id)]['f{0}-r{1}'.format(flow_id, subflow_id)] = {
                'delay' : {
                    'max': max(del_array[key]),
                    'min': min(del_array[key]),
                    'avg': sum(del_array[key])// len(del_array[key])
                },
                'jitter': {
                    'max': max(jit_array[key]),
                    'min': min(jit_array[key]),
                    'avg': sum(jit_array[key])// len(jit_array[key])
                }
            }
            path_info[key] = round( len(del_array[key])/(
                len( del_array['11']) + len(del_array['12']) + len(del_array['13']) ), 2 )
        else:
            flow_data['f{}'.format(flow_id)] = {
                'f{0}-r{1}'.format(flow_id, subflow_id): {
                    'delay' : {
                        'max': max(del_array[key]),
                        'min': min(del_array[key]),
                        'avg': sum(del_array[key])// len(del_array[key])
                    },
                    'jitter': {
                        'max': max(jit_array[key]),
                        'min': min(jit_array[key]),
                        'avg': sum(jit_array[key])// len(jit_array[key])
                    }
                }
            }
            path_info[key] = round( len(del_array[key])/(
                len( del_array['11']) + len(del_array['12']) + len(del_array['13']) ), 2 )

    #  os.system("clear")
    print('path_info: {}\n flow_data: {}'.format(
            json.dumps(path_info, indent=1), json.dumps(flow_data,indent=1) 
            ))
    print("length of glb_del_array: ", len(glb_del_array['12']))
    # client.send_traffic(traffic_info)
    # client.send_delay(flow_data)


"""

        # print('flow_data: ', json.dumps(flow_data,indent=4), end='\n\n')


        # with open('flow_data.json', 'a', encoding='utf-8') as f:
        #     json.dump(flow_data, f, ensure_ascii=False, indent=4)

        
        # print('sent_flow_dataaaaaaaaaaa')
        # cmd_command = 'nikss-ctl table get pipe 0 ingress_tbl_params'
        # cmd_result = json.loads( subprocess.check_output(cmd_command, shell=True))
        # # print(cmd_result)
        # packet_count = 0
        # byte_count = 0

        # for entry in cmd_result['ingress_tbl_params']['entries']:

        #     if entry['action']['id'] == 1:

        #         flow_id = int(entry['action']['parameters'][2]['value'], base=16)//10
        #         packet_count += int(entry['DirectCounter']['ingress_counter_int']['packets'], base=16)
        #         byte_count += int(entry['DirectCounter']['ingress_counter_int']['bytes'], base=16)
        #         # print('packet_count: ', packet_count)
        #         # print('byte_count: ', byte_count)
        #         # print('flow_id: ', flow_id)

        # traffic_info['f{}'.format(flow_id)] = {
        #     'packet_count': packet_count,
        #     'byte_count': byte_count
        # }
        
"""




        # with open('traffic_data.json', 'a', encoding='utf-8') as f:
        #     json.dump(traffic_info, f, ensure_ascii=False, indent=4)


                # print('param: ', entry['action']['parameters'][2], end='\n\n')
                # print('entry: ', entry['DirectCounter'], end='\n\n')
        # print('counter f1: ', cmd_result['ingress_tbl_forward']['entries'])


def handle_pkt_on_thread(pkt):
    global glb_num_total_packets
    glb_num_total_packets = glb_num_total_packets + 1 
    # p = Process(target=handle_pkt, args=(pkt))
    # p.start()

    # threading.Thread(target=handle_pkt, args=(pkt)).start()

def handle_pkt(pkt):
    global t0, t1, glb_del_array, glb_num_total_packets, glb_jit_array
    glb_num_total_packets = glb_num_total_packets + 1
    
    pkt.show2()
    int_data = pkt[INT_AGG]

    int_data.show2()
    return 
    # print(' int_data.flow_id: ', int_data.flow_id)
    # print(' int_data.jitter: ', int_data.jitter)
    # glb_num_total_packets = glb_num_total_packets + 1 
    glb_del_array[str(int_data.flow_id)].append(int_data.delay)
    # jitter = int_data.ingress_timestamp - glb_lst_array[str(int_data.flow_id)]
    glb_jit_array[str(int_data.flow_id)].append(int_data.jitter)
    # glb_lst_array[str(int_data.flow_id)] = int_data.ingress_timestamp

    if (time.time() - t0 ) > 2.0:
        t0 = time.time()
        # jit_array = glb_jit_array
        # del_array = glb_del_array
        # threading.Thread(target=handle_flow_data,args=(glb_del_array,glb_jit_array)).start()
        # p = Process(target=handle_flow_data,args=(glb_del_array, glb_jit_array))
        # p.start()
        handle_flow_data(glb_del_array, glb_jit_array)
        # glb_del_array = {'11': [], '12': [], '13': [], '21': [], '22': [], '23': []}
        # glb_jit_array = {'11': [], '12': [], '13': [], '21': [], '22': [], '23': []}
        
    sys.stdout.flush()
    
"""
        # print(del_array)

        # flow_data = {}     
        # for key in del_array.keys():
        #     # print('del_array[key]', del_array[key])
        #     if ( len(del_array[key]) == 0): 
        #         continue
        #     # print('key', key)

        #     flow_id = '{}'.format(int(key)//10)
        #     subflow_id = '{}'.format(int(key)%10 )


        #     if 'f{}'.format(flow_id) in flow_data.keys():
        #         flow_data['f{}'.format(flow_id)]['f{0}-r{1}'.format(flow_id, subflow_id)] = {
        #             'delay' : {
        #                 'max': max(del_array[key]),
        #                 'min': min(del_array[key]),
        #                 'avg': sum(del_array[key])/ len(del_array[key])
        #             },
        #             'jitter': {
        #                 'max': max(jit_array[key]),
        #                 'min': min(jit_array[key]),
        #                 'avg': sum(jit_array[key])/ len(jit_array[key])
        #             }
        #         }
        #     else:
        #         flow_data['f{}'.format(flow_id)] = {
        #             'f{0}-r{1}'.format(flow_id, subflow_id): {
        #                 'delay' : {
        #                     'max': max(del_array[key]),
        #                     'min': min(del_array[key]),
        #                     'avg': sum(del_array[key])/ len(del_array[key])
        #                 },
        #                 'jitter': {
        #                     'max': max(jit_array[key]),
        #                     'min': min(jit_array[key]),
        #                     'avg': sum(jit_array[key])/ len(jit_array[key])
        #                 }
        #             }
        #         }
        # print('flow_data: ', flow_data)    

    # if (time.time() - t0 ) > 2.0:
    #     # print(del_array)
    #     t0 = time.time()
    #     flow_data = {}     
    #     for key in del_array.keys():
    #         # print('del_array[key]', del_array[key])
    #         if ( len(del_array[key]) == 0): 
    #             continue
    #         # print('key', key)

    #         flow_id = '{}'.format(int(key)//10)
    #         subflow_id = '{}'.format(int(key)%10 )
    #         if 'f{}'.format(flow_id) in flow_data.keys():
    #             flow_data['f{}'.format(flow_id)]['f{0}-r{1}'.format(flow_id, subflow_id)] = {
    #                 'delay' : {
    #                     'max': max(del_array[key]),
    #                     'min': min(del_array[key]),
    #                     'avg': sum(del_array[key])/ len(del_array[key])
    #                 }
    #             }
    #         else:
    #             flow_data['f{}'.format(flow_id)] = {
    #                 'f{0}-r{1}'.format(flow_id, subflow_id): {
    #                     'delay' : {
    #                         'max': max(del_array[key]),
    #                         'min': min(del_array[key]),
    #                         'avg': sum(del_array[key])/ len(del_array[key])
    #                     }
    #                 }
    #             }

    #     del_array = {'11': [], '12': [], '13': []}
        #  print('flow_data: ', flow_data)

"""




def sniff_on_thread(iface, filter):
    return
    # threading.Thread(target=sniff_packets, args=(iface, filter)).start()
    p = Process(target=sniff_packets, args=(iface, filter))
    p.start()
    
def sniff_packets(iface, filter):
    sniff(iface = iface, filter=filter, store=0,
          prn = lambda x: handle_pkt(x))

def main():
    global t0, glb_del_array, glb_jit_array
    # bind_layers(INT_AGG, INT_MD)
    bind_layers(UDP, INT_AGG, dport=args.port)
    iface = args.interface
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    t0 = time.time()
    # sniff(iface = args.interface, filter="dst port 35000",
    #       prn = lambda x: handle_pkt(x))
    sniff_packets(iface = args.interface, filter="dst port 35000")

    return
    while True:
        if (time.time() - t0 ) > 2.0:

            jit_array = glb_jit_array
            del_array = glb_del_array

            glb_del_array = {'11': [], '12': [], '13': []}
            glb_jit_array = {'11': [], '12': [], '13': []} 


            # print(del_array)
            t0 = time.time()
            flow_data = {}     
            for key in del_array.keys():
                # print('del_array[key]', del_array[key])
                if ( len(del_array[key]) == 0): 
                    continue
                # print('key', key)

                flow_id = '{}'.format(int(key)//10)
                subflow_id = '{}'.format(int(key)%10 )


                if 'f{}'.format(flow_id) in flow_data.keys():
                    flow_data['f{}'.format(flow_id)]['f{0}-r{1}'.format(flow_id, subflow_id)] = {
                        'delay' : {
                            'max': max(del_array[key]),
                            'min': min(del_array[key]),
                            'avg': sum(del_array[key])/ len(del_array[key])
                        },
                        'jitter': {
                            'max': max(jit_array[key]),
                            'min': min(jit_array[key]),
                            'avg': sum(jit_array[key])/ len(jit_array[key])
                        }
                    }
                else:
                    flow_data['f{}'.format(flow_id)] = {
                        'f{0}-r{1}'.format(flow_id, subflow_id): {
                            'delay' : {
                                'max': max(del_array[key]),
                                'min': min(del_array[key]),
                                'avg': sum(del_array[key])/ len(del_array[key])
                            },
                            'jitter': {
                                'max': max(jit_array[key]),
                                'min': min(jit_array[key]),
                                'avg': sum(jit_array[key])/ len(jit_array[key])
                            }
                        }
                    }
            print('flow_data', flow_data)


if __name__ == '__main__':
    try:
        main()
        print('\nnum_packets: ', glb_num_total_packets)
    except KeyboardInterrupt:
        print('\nnum_packets: ', glb_num_total_packets)
        exit()
