import subprocess
import pathlib
import configparser


def main():
    config = configparser.ConfigParser()
    if not config.read('config.ini'):
        raise RuntimeError('config.ini not found')
    subprocess.run([config.get('MITM', 'mitmdump_executable_path'),
                    '--allow-hosts', config.get('MITM', 'allowed_hosts'),
                    '--scripts', pathlib.Path(__file__).parent / 'swmitm' / 'mitm.py',
                    '--mode', config.get('Settings', 'proxy_mode'),
                    '--listen-port', config.get('Settings', 'proxy_port'),
                    '-q'])


if __name__ == '__main__':
    main()
