import sys

def main():
    args = sys.argv[1:]
    # Create domain.cnf, templated on rootCA.cnf but with a different IP.
    new_lines = []
    config_dir = "configs/"
    with open(config_dir + "rootCA.cnf") as f:
        lines = [line.rstrip() for line in f]
        for line in lines:
            if ("FQDN =" in line):
               new_lines.append("FQDN = " + args[0] + "\n")
            else:
               new_lines.append(line + "\n") 
    with open(config_dir + "domain.cnf", "w") as out:
        out.writelines(new_lines)

    # Create domain.ext, templated on domain_template.ext but with correct IP.
    new_lines = []
    with open(config_dir + "domain_template.ext") as f:
        lines = [line.rstrip() for line in f]
        for line in lines:
            if ("IP.1" in line):
               new_lines.append("IP.1 = " + args[0] + "\n")
            else:
               new_lines.append(line + "\n") 
    with open(config_dir + "domain.ext", "w") as out:
        out.writelines(new_lines)



if __name__ == "__main__":
    main()
