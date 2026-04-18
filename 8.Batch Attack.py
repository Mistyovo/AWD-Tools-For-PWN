import subprocess
import time

hosts = []
ports = []
exp = "exp.py"

# generate hosts and ports



# attack
key_word = "FOUND FLAG: "
for host in hosts:
    for port in ports:
        print(f"Attacking {host}:{port} ...")
        time.sleep(1)
        result = subprocess.run(["python3", exp, host, str(port)], capture_output=True, text=True)
        if key_word in result.stdout:
            for line in result.stdout.split('\n'):
                if key_word in line:
                    with open("flags.txt", "a") as f:
                        f.write(f"Host: {host}, Port: {port}, Output: {line}\n")
