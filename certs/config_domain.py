import os

CONFIG_DIR = "config"

PROXY_CNF_TEMPLATE = os.path.join(CONFIG_DIR, "proxy.cnf.template")
PROXY_CNF_OUT = os.path.join(CONFIG_DIR, "proxy.cnf")

PROXY_EXT_TEMPLATE = os.path.join(CONFIG_DIR, "proxy.ext.template")
PROXY_EXT_OUT = os.path.join(CONFIG_DIR, "proxy.ext")


def main(ip_addr: str):
    # Create the configuration file used to create the leaf certificate,
    # using the given template but overwriting the IP
    new_lines = []
    with open(PROXY_CNF_TEMPLATE, "r", encoding="utf-8") as f:
        lines = [line.rstrip() for line in f]
        for line in lines:
            if "FQDN =" in line:
                new_lines.append("FQDN = " + ip_addr + "\n")
            else:
                new_lines.append(line + "\n")
    with open(PROXY_CNF_OUT, "w", encoding="utf-8") as out:
        out.writelines(new_lines)

    # Create the extensions file used to create the leaf certificate,
    # using the given template but overwriting the IP
    new_lines = []
    with open(PROXY_EXT_TEMPLATE, encoding="utf-8") as f:
        lines = [line.rstrip() for line in f]
        for line in lines:
            if "IP.1" in line:
                new_lines.append("IP.1 = " + ip_addr + "\n")
            else:
                new_lines.append(line + "\n")

    with open(PROXY_EXT_OUT, "w", encoding="utf-8") as out:
        out.writelines(new_lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "ip_addr",
        default="127.0.0.1",
        help="IP address of the proxy; usually 127.0.0.1 if hosted locally",
    )
    args = parser.parse_args()

    main(args.ip_addr)
