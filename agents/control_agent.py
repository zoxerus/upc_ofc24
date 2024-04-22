#!/usr/bin/python3.8


from flask import Flask, request
import requests
import sys
import subprocess
import json

import agents._flows_dictionary as fd

# Here select the interfaces used by the P4 switch
if0 = [int( subprocess.run('cat /sys/class/net/em0/ifindex',shell=True,capture_output=True).stdout), '00:dd:85:f3:dd:0d']
if1 = [int( subprocess.run('cat /sys/class/net/em1/ifindex',shell=True,capture_output=True).stdout), '00:dd:85:f3:dd:1d']
if2 = [int( subprocess.run('cat /sys/class/net/eno2/ifindex',shell=True,capture_output=True).stdout), '00:05:85:f3:94:00']
if3 = [int( subprocess.run('cat /sys/class/net/eno3/ifindex',shell=True,capture_output=True).stdout), '00:05:85:f3:94:5d']
if4 = [int( subprocess.run('cat /sys/class/net/eno4/ifindex',shell=True,capture_output=True).stdout), '00:dd:85:f3:dd:4d']
if5 = [int( subprocess.run('cat /sys/class/net/veth0/ifindex',shell=True,capture_output=True).stdout), '00:05:85:f3:94:5d']

print('\nif0ndx: ', if0[0]) 
print('\nif1ndx: ', if1[0]) 
print('\nif2ndx: ', if2[0])
print('\nif3ndx: ', if3[0])
print('\nif4ndx: ', if4[0])
print('\nif5ndx: ', if5[0])

# Flow definition 
flows = {
     'f1' : "192.168.30.10/32",
     'f2' : "192.168.30.11/32"
}

# to start a web app
app = Flask('niksss control agent')

# listen to url http://serveraddress/policy
@app.route('/policy', methods=['POST'])
def set_policy():
        print(json.dumps( request.json, indent= 2) )
        try: 
            for flow in request.json:
                # extract flow id: for example flow id for f22 is 22
                fid = ''.join( [s for s in list(filter(lambda x: x.isdigit(), flow))] )
                fid += '0'
                # print('flow:', flow)
                # print('fid:', fid)
                load_percent = []
                for subFlow in request.json[flow]['policy']:
                    # print ( 'subFlow_percent: ' ,request.json[flow]['policy'][subFlow])
                    load_percent.append(int( request.json[flow]['policy'][subFlow]*10.24 ) )
                # print(load_percent)
                command = 'nikss-ctl table update pipe 0 ingress_tbl_params action id 1 key {} {} data {} {} {}'.format(
                     if0[0], flows[flow], load_percent[0], load_percent[0] + load_percent[1], fid
                )
                # print(command)
                res = subprocess.run(command, shell=True, capture_output=True)
                print(res.stdout, res.stderr)

        except Exception as e:
            print(e)
            return 'Error'
            print(e)
            
        return 'OK'


if __name__ == '__main__':
    # start the server using the ip and port number indicated below
    app.run(host='0.0.0.0', port=8080, debug=True)