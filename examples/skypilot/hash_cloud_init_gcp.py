import hashlib
import os

cloud_init_config_human_readable = """#cloud-config
        users:
          - name: gcpuser
            sudo: ['ALL=(ALL) NOPASSWD:ALL']
            groups: sudo
            shell: /bin/bash
            ssh_authorized_keys:
              - {0}
        """
cloud_init_config_from_json = "#cloud-config\n        users:\n          - name: gcpuser\n            sudo: ['ALL=(ALL) NOPASSWD:ALL']\n            groups: sudo\n            shell: /bin/bash\n            ssh_authorized_keys:\n              - {0}\n\n        "

PUBLIC_SSH_KEY_PATH='~/.ssh/sky-key.pub'

def hash_cloud_init_gcp():
    public_key_path = os.path.expanduser(PUBLIC_SSH_KEY_PATH)
    with open(public_key_path, 'r') as f:
        public_key = f.read()
    script = cloud_init_config_from_json.format(public_key)
    print(script)
    return hashlib.sha256(script.encode()).hexdigest()

def main():
    print(hash_cloud_init_gcp()) 

if __name__ == "__main__":
    main()

