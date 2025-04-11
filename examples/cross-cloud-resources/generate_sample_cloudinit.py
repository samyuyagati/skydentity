"""
Script to generate the `sample_cloudinit.yaml` file,
containing the script contents in `sample_vm_script.py`

Requires `ruamel.yaml` to be installed via pip.
(This is required to preserve comments in the cloud-init YAML file.)
"""

from ruamel.yaml import YAML

# load yaml file
yaml = YAML()
with open("./sample_cloudinit_template.yaml", "r", encoding="utf-8") as template_file:
    template_yaml = yaml.load(template_file)

# load script file
with open("./sample_vm_script.py", "r", encoding="utf-8") as script_file:
    script_contents = script_file.read()

# inject the script
print(template_yaml)
write_files = template_yaml["write_files"]
file_dict = write_files[0]
file_dict["content"] = script_contents
print(template_yaml)

# set width to a large number so that the script does not wrap
yaml.width = 10000

# save new yaml file
with open("./sample_cloudinit.yaml", "w", encoding="utf-8") as yaml_file:
    yaml.dump(template_yaml, yaml_file)
