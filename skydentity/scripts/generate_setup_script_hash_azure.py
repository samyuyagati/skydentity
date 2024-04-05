import textwrap
import os
import hashlib

with open(os.path.expanduser('~/.ssh/sky-key.pub')) as f:
    ssh_key = f.read().strip()

# Generates the hash of the cloud init script for skypilot given the currently used ssh key.
# IMPORTANT, there is technically a difference here between the cloud init set by skypilot and the one generated here.
# The user is azureuser, and skypilot ends up filling out a mini template with the user being used. This is a typical filled out version.
text = textwrap.dedent("""\
            #cloud-config
            users:
              - name: azureuser
                sudo: ['ALL=(ALL) NOPASSWD:ALL']
                groups: sudo
                shell: /bin/bash
                ssh_authorized_keys:
                  - {0}
            runcmd:
              - sed -i 's/#Banner none/Banner none/' /etc/ssh/sshd_config
              - echo '\\nif [ ! -f "/tmp/__restarted" ]; then\\n  sudo systemctl restart ssh\\n  sleep 2\\n  touch /tmp/__restarted\\nfi' >> /home/azureuser/.bashrc
              - usermod -aG docker azureuser
            write_files:
              - path: /etc/apt/apt.conf.d/20auto-upgrades
                content: |
                  APT::Periodic::Update-Package-Lists "0";
                  APT::Periodic::Download-Upgradeable-Packages "0";
                  APT::Periodic::AutocleanInterval "0";
                  APT::Periodic::Unattended-Upgrade "0";
              - path: /etc/apt/apt.conf.d/10cloudinit-disable
                content: |
                  APT::Periodic::Enable "0";
        """).format(ssh_key)

print(text.encode("utf-8"))

print(hashlib.sha256(text.encode("utf-8")).hexdigest())
