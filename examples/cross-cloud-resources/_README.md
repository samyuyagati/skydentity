THIS IS INFORMATION IS ALL LOCAL TO MY COMPUTER

# Creating the VM

Run the following to create the VM while monitoring via mitmproxy:
```sh
env $(cat ../.env.mitmproxy | xargs) python3 examples/cross-cloud-resources/create_vm_azure.py
```

# Running proxies

Each proxy has a `_run_proxy_with_env.sh` file at the root; running
```sh
kitty --session=$PWD/_local/all-proxies.session
```
at the root of the repository will start all proxies



## TODO

- use cloudinit to create a script and run it on VM start (base64 encode the script, and have cloudinit write it to disk)
