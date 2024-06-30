import subprocess
import multiprocessing

config_file = "config0"
with open(config_file, "r") as file:
    lines = file.readlines()

def execute_ssh(pem_file, ip_address, id, tt):
    ssh_command = f"ssh -i {pem_file} ubuntu@{ip_address} 'cat /home/ubuntu/benchmark-logs/benchmark.log'"

    try:
        ssh_process = subprocess.Popen(ssh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        if ssh_process.returncode == 0:
            output_file = f"./results/{tt}/{id}.txt"
            with open(output_file, "w") as f:
                f.write(stdout.decode())
            print(f"Data from {ip_address} saved to {output_file}")
        else:
            print(f"Error while executing SSH command for {ip_address}: {stderr.decode()}")
    except Exception as e:
        print(f"An error occurred with {ip_address}: {e}")

if __name__ == '__main__':
    import time
    t = time.time()
    import os
    os.makedirs(f"./results/{t}")
    pool = multiprocessing.Pool()
    i = 0
    for line in lines:
        pem_file, ip_address = line.strip().split()
        pool.apply_async(execute_ssh, args=(pem_file, ip_address, i, t))
        i += 1

    pool.close()
    pool.join()
