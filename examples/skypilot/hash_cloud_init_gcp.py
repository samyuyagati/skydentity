import hashlib
import os

cloud_init_config = """#cloud-config
        users:
          - name: gcpuser
            sudo: ['ALL=(ALL) NOPASSWD:ALL']
            groups: sudo
            shell: /bin/bash
            ssh_authorized_keys:
              - {0}
        """

PUBLIC_SSH_KEY_PATH='~/.ssh/sky-key.pub'

def hash_cloud_init_gcp():
    public_key_path = os.path.expanduser(PUBLIC_SSH_KEY_PATH)
    with open(public_key_path, 'r') as f:
        public_key = f.read()
    script = cloud_init_config.format(public_key)
    return hashlib.sha256(script.encode()).hexdigest()

def main():
    print(hash_cloud_init_gcp()) 

if __name__ == "__main__":
    main()

