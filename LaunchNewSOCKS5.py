import boto3
import json
import time
import random
import threading

INSTANCES_TO_LAUNCH = 5
SOCKS_USERNAME = "coyote"

MAX_THREADS = 10

client = boto3.client('ec2',region_name='us-west-1')
ec2 = boto3.resource('ec2',region_name='us-west-1') 
ssm_client = boto3.client('ssm', region_name='us-west-1') 

def generate_password(length=16):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    password = "".join([random.choice(chars) for _ in range(length)])
    return password

def configure_instance(client, instance, username, password):
    client.send_command(
        InstanceIds=[instance.id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                f"""echo "username={username}\npassword={password}" > /home/ubuntu/credentials.config""",
                f"sudo service socks restart",
            ]
        }
    )

def wait_for_ssm(client, instance):
    for _ in range(1, 100):
        response = client.describe_instance_information(Filters=[{'Key': 'InstanceIds', 'Values': [instance.id]}])
        if len(response["InstanceInformationList"]) > 0 and \
                response["InstanceInformationList"][0]["PingStatus"] == "Online" and \
                response["InstanceInformationList"][0]["InstanceId"] == instance.id:
            break
        time.sleep(1)

proxy_servers = []
def setup_instance(instance, debug):
    global proxy_servers, ec2, ssm_client

    instance = ec2.Instance(id=instance['InstanceId'])
    if debug:
        print(f"Waiting for instance {instance.id} to start...")
    instance.wait_until_running()
    if debug:
        print(f"Waiting for SSM to be available on instance {instance.id}...")
    wait_for_ssm(ssm_client, instance)

    SOCKS_PASSWORD = generate_password()

    if debug:
        print(f"Configuring instance {instance.id}...")
    configure_instance(ssm_client, instance, SOCKS_USERNAME, SOCKS_PASSWORD)

    public_ip = instance.public_ip_address
    proxy_servers.append({
        "ip": public_ip,
        "port": 1080,
        "username": SOCKS_USERNAME,
        "password": SOCKS_PASSWORD,
        "instance_id": instance.id
    })
    if debug:
        print(f"Instance {instance.id} started with public IP {public_ip}")

def launch(num_instances, debug=False):
    if debug:
        print("Launching instances...")
    try:
        instances = client.run_instances(
            LaunchTemplate={
                'LaunchTemplateId': 'lt-0595e64766e1e9cc5'
            },
            IamInstanceProfile={
                'Name': "AmazonSSMRoleForInstancesQuickSetup"
            },
            MinCount=1,
            MaxCount=num_instances
        )
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, please terminate the instances...")

    threads = []

    for instance in instances['Instances']:
        while threading.active_count() > MAX_THREADS:
            time.sleep(1)
        thread = threading.Thread(target=setup_instance, args=(instance,debug), daemon=True)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if debug:
        for proxy_server in proxy_servers:
            print(f"{proxy_server['username']}:{proxy_server['password']}@{proxy_server['ip']}:{proxy_server['port']}")
        # print(f"{proxy_server['ip']}:{proxy_server['port']}:{proxy_server['username']}:{proxy_server['password']}") # foxyproxy format


    old_proxy_servers = []
    try:
        with open('proxy_servers.json') as json_file:
            old_proxy_servers = json.load(json_file)
    except FileNotFoundError:
        pass
    proxy_servers_to_write = proxy_servers
    proxy_servers_to_write.extend(old_proxy_servers)

    if debug:
        print("Writing proxy servers to file...")
    with open('proxy_servers.json', 'w') as outfile:
        json.dump(proxy_servers_to_write, outfile)

    return proxy_servers

def main():
    launch(INSTANCES_TO_LAUNCH, True)

if __name__ == "__main__":
    main()