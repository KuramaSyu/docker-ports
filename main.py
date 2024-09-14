import os
import yaml
import re
import click
from collections import defaultdict
from typing import *
from tabulate import tabulate
import subprocess

def get_running_containers(path: str) -> str:
    try:
        # Run the 'docker compose ps' command in the specified directory to check the status of the containers
        result = subprocess.run(
            ["docker", "compose", "ps", "--services", "--filter", "status=running"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=path  # Specify the working directory
        )
        # If any services are running, this will not be empty
        return result.stdout.strip()
    except Exception as e:
        print(f"Error checking Docker Compose status: {e}")
        return ""

def get_traefik_domain(labels: dict, port: Optional[Union[str, int]] = None) -> Union[None, str, List[str]]:
    """
    Check if the given port is bound to a Traefik domain based on Docker Compose labels.
    
    Args:
        labels (dict): A dictionary of labels from the Docker Compose file.
        port (str, int, or None): The port to check, or None to retrieve all domains.
    
    Returns:
        str: The domain bound to the port.
        list: A list of domains if no port is specified.
        None: If no domain is found or Traefik is not enabled.
    """
    # Ensure labels are a dictionary and Traefik is enabled
    if not isinstance(labels, dict):
        return None

    if labels.get("traefik.enable", False) != True:
        return None
    
    # If a port is provided, convert it to string for comparison
    if port is not None:
        port = str(port)

    domains = []

    # Compile regex pattern for Traefik service port labels
    port_label_pattern = re.compile(r'traefik\.http\.services\.((?:\w|[-])+)\.loadbalancer\.server\.port')

    for label, value in labels.items():
        # If port is specified, only process labels that match the given port
        match = port_label_pattern.match(label)
        if match and (port is None or str(value) == port):
            service_name = match.group(1)
            # Remove '-service' suffix if present
            service_name = service_name.removesuffix("-service")
            
            # Check for a Traefik rule that binds this service to a domain
            domain_label = f'traefik.http.routers.{service_name}.rule'
            rule = labels.get(domain_label)
            if rule:
                # Extract domain from the rule (expecting something like Host(`example.com`))
                domain_match = re.search(r"Host\(`([^`]*)`\)", rule)
                if domain_match:
                    domains.append(domain_match.group(1))
    
    # If port is specified, return the first domain or 'localhost' if no domain is found
    if port is not None:
        return domains[0] if domains else None

    # If no port is specified, return the list of all found domains
    return domains if domains else None

# Function to scan directories for Docker Compose files
def scan_directories(base_dir, max_depth) -> Dict[str, List[Tuple[str, str | None]]]:
    services_ports: Dict[str, Set[Row]] = defaultdict(set)
    compose_file_patterns = re.compile(r'(docker-compose|compose)\.ya?ml$', re.IGNORECASE)

    def scan_directory(directory, current_depth):
        if current_depth > max_depth:
            return

        for root, dirs, files in os.walk(directory):
            for file in files:
                if compose_file_patterns.search(file):
                    file_path = os.path.join(root, file)
                    try:
                        parse_compose_file(file_path, services_ports)
                    except Exception as e:
                        click.echo(f"Error scanning {file_path}: {e}")

            for dir in dirs:
                scan_directory(os.path.join(root, dir), current_depth + 1)
            break

    def parse_compose_file(file_path, services_ports):
        print(f"Scanning {file_path}")
        folder_path = os.path.dirname(file_path)
        with open(file_path, 'r') as stream:
            try:
                data: None | Any = yaml.safe_load(stream)
                if data is None or 'services' not in data:
                    return 
                running_containers = get_running_containers(folder_path)
                for service, service_data in data['services'].items():
                    labels = service_data.get('labels', {})
                    # TODO: handeling when labels are list of strings
                    if not 'ports' in service_data and not "labels" in service_data:
                        continue
                    if not 'ports' in service_data:
                        service_ports = add_domains_to_service_ports(services_ports, labels, service, running_containers)
                        continue
                        
                    ports: List[str] | str = service_data['ports']
                    if isinstance(ports, str):
                        if " " in ports:
                            # multiple ports separated by space
                            ports: List[str] = [x for x in ports.split(" ")]
                        else:
                            # one port pair
                            ports: List[str] = [ports]
                    for port_pair in ports:
                        service_ports = add_to_service_ports(services_ports, port_pair, labels, service, running_containers)
                    service_ports = add_domains_to_service_ports(services_ports, labels, service, running_containers)

            except yaml.YAMLError as exc:
                click.echo(f"Error parsing YAML file {file_path}: {exc}")

    def add_domains_to_service_ports(service_ports, labels: Dict[str, Any], service: str, running_containers: str) -> Dict[str, Set[Row]]:
        domains = get_traefik_domain(labels)
        if not domains:
            return service_ports
        for domain in domains:
            is_running = service in running_containers
            rows = service_ports.get(service, set())
            if not any(r.domain == domain for r in rows):
                service_ports[service].add(Row(service, None, domain, is_running))
        return service_ports

    def add_to_service_ports(service_ports, ports: str, labels: Dict[str, Any], service: str, running_containers: str) -> Dict[str, Set[Row]]:
        extern, intern_ = None, None
        try:
            extern, intern_ = ports.split(":")
        except ValueError:
            extern, intern_ = ports, ports
        domain = get_traefik_domain(labels, intern_)
        is_running = service in running_containers
        rows = service_ports[service]
        row = Row(service, extern, domain, is_running)
        if row not in rows:
            rows.add(row)
        else:
            for r in rows:
                if r == row:
                    r.add_domain(domain)

    scan_directory(base_dir, 0)
    return services_ports

class Row:
    def __init__(self, service, port, domain: str | None, is_running: bool):
        self.service = service
        self.port = port
        self.domain = domain
        self.is_running = is_running
    # use service as hash
    def __hash__(self):
        return hash(self.service)

    def is_docker_container_running(self):
        try:
            # Run the 'docker ps' command with the filter for the container name
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.service}", "--format", "{{.Names}}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Check if the container name is in the result
            return self.service in result.stdout.strip().split('\n')
        except Exception as e:
            print(f"Error checking container: {e}")
            return False

    def add_domain(self, domain: str | None):
        if domain:
            self.domain = domain

    def __repr__(self):
        return f"Row({self.service}, {self.port}, {self.domain}, {self.is_running})"

    def __eq__(self, other):
        return self.service == other.service and (self.port == other.port) if all([self.port, other.port]) else (self.domain == other.domain)
# Main CLI definition using Click
@click.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, readable=True))
@click.argument('depth', type=int)
@click.option('--online', is_flag=True, help="Only show online services.")
@click.option('--offline', is_flag=True, help="Only show offline services.")
@click.option('--has-domain', is_flag=True, help="Only show services with a domain.")
def main(directory, depth, online, offline, has_domain):
    """
    Scan a DIRECTORY for Docker Compose files up to a specified DEPTH of subdirectories.
    """
    online_flag, offline_flag, has_domain_flag = online, offline, has_domain
    click.echo(f"Scanning '{directory}' up to depth {depth} for Docker Compose files...")

    # filter duplicate ports
    services_ports: Dict[str, Set[Row]] = scan_directories(directory, depth)
    
    if not services_ports:
        click.echo("No Docker Compose files found.")
        return

    click.echo("\nExposed ports for services:")

    data_as_rows: List[Row] = [entry for values in services_ports.values() for entry in values]
    print(data_as_rows)
    
    if online_flag:
        data_as_rows = [row for row in data_as_rows if row.is_docker_container_running()]

    if offline_flag:
        data_as_rows = [row for row in data_as_rows if not row.is_docker_container_running()]

    if has_domain_flag:
        data_as_rows = [row for row in data_as_rows if row.domain]

    tabulated_data = [
        [
            row.service, 
            row.port, 
            row.domain, 
            "Online" if row.is_running else "Offline"
        ] for row in data_as_rows
    ]
    click.echo(tabulate(tabulated_data, tablefmt="rounded_outline", headers=["Service", "Port", "Domain", "Status"]))

# Entry point for the CLI
if __name__ == "__main__":
    main()
