import subprocess
import json
import client
import time
import os


traffic_info = {}
packet_count = 0
byte_count = 0

t0 = time.time()
while True:
    if (time.time() - t0 > 3):
        cmd_command = 'nikss-ctl table get pipe 0 ingress_tbl_params'
        cmd_result = json.loads( subprocess.check_output(cmd_command, shell=True))

        for entry in cmd_result['ingress_tbl_params']['entries']:

            if entry['action']['id'] == 1:
                flow_id = int(entry['action']['parameters'][2]['value'], base=16)//10
                packet_count = int(entry['DirectCounter']['ingress_counter_int']['packets'], base=16)
                byte_count = int(entry['DirectCounter']['ingress_counter_int']['bytes'], base=16)
                traffic_info['f{}'.format(flow_id)] = {
                    'packet_count': packet_count,
                    'byte_count': byte_count
                }
                # print('packet_count: ', packet_count)
                # print('byte_count: ', byte_count)
                # print('flow_id: ', flow_id)
        os.system("clear")
        print(json.dumps(traffic_info, indent=2), end = '\n\n')
        client.send_traffic(traffic_info)

        t0 = time.time()