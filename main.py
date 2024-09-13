import os
import yaml
import re
import click
from collections import defaultdict

# Function to scan directories for Docker Compose files
def scan_directories(base_dir, max_depth):
    services_ports = defaultdict(list)
    compose_file_patterns = re.compile(r'(docker-compose|compose)\.ya?ml$', re.IGNORECASE)

    def scan_directory(directory, current_depth):
        if current_depth > max_depth:
            return

        for root, dirs, files in os.walk(directory):
            for file in files:
                print(f"{file=}")
                if compose_file_patterns.search(file):
                    print("matched")
                    file_path = os.path.join(root, file)
                    parse_compose_file(file_path, services_ports)

            for dir in dirs:
                scan_directory(os.path.join(root, dir), current_depth + 1)
            break

    def parse_compose_file(file_path, services_ports):
        with open(file_path, 'r') as stream:
            try:
                data = yaml.safe_load(stream)
                if 'services' in data:
                    for service, service_data in data['services'].items():
                        if 'ports' in service_data:
                            ports: List[str] | str = service_data['ports']
                            if isinstance(ports, str):
                                if " " in ports:
                                    ports: List[str] = [x for x in ports.split(" ")]
                                else:
                                    services_ports[service].append(port.split(":")[0])
                                    continue
                            for port in ports:
                                services_ports[service].append(port.split(":")[0])
            except yaml.YAMLError as exc:
                click.echo(f"Error parsing YAML file {file_path}: {exc}")

    scan_directory(base_dir, 0)
    return services_ports

# Main CLI definition using Click
@click.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, readable=True))
@click.argument('depth', type=int)
def main(directory, depth):
    """
    Scan a DIRECTORY for Docker Compose files up to a specified DEPTH of subdirectories.
    """
    click.echo(f"Scanning '{directory}' up to depth {depth} for Docker Compose files...")

    services_ports = scan_directories(directory, depth)

    if services_ports:
        click.echo("\nExposed ports for services:")
        for service, ports in services_ports.items():
            click.echo(f"Service '{service}' exposes ports: {', '.join(ports)}")
    else:
        click.echo("No services with exposed ports found.")

# Entry point for the CLI
if __name__ == "__main__":
    main()
