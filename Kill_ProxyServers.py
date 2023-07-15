import boto3
import json
import os

client = boto3.client('ec2',region_name='us-west-1')
ec2 = boto3.resource('ec2',region_name='us-west-1') 

# read instances from proxy_servers.json, which is a list of dicts containing instance_id
with open('proxy_servers.json') as json_file:
    data = json.load(json_file)

if len(data) == 0:
    print("No proxies to kill")
    exit(0)

instance_ids = [i['instance_id'] for i in data]
ec2.instances.filter(InstanceIds=instance_ids).terminate()
print(f"Terminated {len(instance_ids)} instances")

with open('proxy_servers.json', 'w') as outfile:
    json.dump([], outfile)