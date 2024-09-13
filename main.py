import os
import yaml
import re
import click
from collections import defaultdict
from typing import *

def get_traefik_domain(labels, port) -> str:
    """
    Check if the given port is bound to a Traefik domain based on Docker Compose labels.

    Args:
        labels (dict): A dictionary of labels from the Docker Compose file.
        port (str or int): The port to check.

    Returns:
        str: The domain bound to the port, or 'localhost' if no domain is found.
    """
    # Check if Traefik is enabled
    if not isinstance(labels, dict):
        return "localhost"

    if labels.get("traefik.enable", False) != True:
        return "localhost"
    
    # Convert port to string (as labels might store port numbers as strings)
    port = str(port)

    # Search for the Traefik service port label
    port_label_pattern = re.compile(r'traefik\.http\.services\.(\w+)\.loadbalancer\.server\.port')
    for label, value in labels.items():
        match = port_label_pattern.match(label)
        if match and value == port:
            service_name = match.group(1)
            
            # Check if there's a Traefik rule that binds this service to a domain
            domain_label = f'traefik.http.routers.{service_name}.rule'
            rule = labels.get(domain_label)
            if rule:
                # Extract domain from the rule (expecting something like Host(`example.com`))
                domain_match = re.search(r"Host\(`([^`]*)`\)", rule)
                if domain_match:
                    return domain_match.group(1)
    
    return "localhost"


# Function to scan directories for Docker Compose files
def scan_directories(base_dir, max_depth) -> Dict[str, List[Tuple[str, str]]]:
    services_ports = defaultdict(list)
    compose_file_patterns = re.compile(r'(docker-compose|compose)\.ya?ml$', re.IGNORECASE)

    def scan_directory(directory, current_depth):
        if current_depth > max_depth:
            return

        for root, dirs, files in os.walk(directory):
            for file in files:
                if compose_file_patterns.search(file):
                    file_path = os.path.join(root, file)
                    parse_compose_file(file_path, services_ports)

            for dir in dirs:
                scan_directory(os.path.join(root, dir), current_depth + 1)
            break

    def parse_compose_file(file_path, services_ports):
        with open(file_path, 'r') as stream:
            try:
                data: None | Any = yaml.safe_load(stream)
                if data is not None and 'services' in data:
                    for service, service_data in data['services'].items():
                        labels = service_data.get('labels', {})
                        # TODO: handeling when labels are list of strings
                        if 'ports' in service_data:
                            ports: List[str] | str = service_data['ports']
                            if isinstance(ports, str):
                                if " " in ports:
                                    ports: List[str] = [x for x in ports.split(" ")]
                                else:
                                    service_ports = add_to_service_ports(services_ports, ports, labels, service)
                                    continue
                            for port_pair in ports:
                                service_ports = add_to_service_ports(services_ports, port_pair, labels, service)
            except yaml.YAMLError as exc:
                click.echo(f"Error parsing YAML file {file_path}: {exc}")

    def add_to_service_ports(service_ports, ports: str, labels: Dict[str, Any], service: str):
        extern, intern_ = ports.split(":")
        domain = get_traefik_domain(labels, intern_)
        port = extern if domain == "localhost" else intern_
        services_ports[service].append((port, domain))
        return services_ports
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

    services_ports: Dict[str, List[str]] = scan_directories(directory, depth)
    services_ports: Dict[str, Set[str]]  = {k: set(v) for k, v in services_ports.items()}

    if services_ports:
        click.echo("\nExposed ports for services:")
        for service, ports in services_ports.items():
            click.echo(f"{service}: {'; '.join(f'{port} ({domain})' for port, domain in ports)}")
    else:
        click.echo("No services with exposed ports found.")

# Entry point for the CLI
if __name__ == "__main__":
    main()
