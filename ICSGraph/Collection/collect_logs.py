#!/usr/bin/env python3
"""
Velociraptor Log Collector

Collects forensic logs from Velociraptor clients for a given hunt.
Downloads Sysmon, Process List, and Listener data from Windows and Linux endpoints.

Usage:
    python collect_logs.py <hunt_id> [--config CONFIG_PATH] [--output OUTPUT_DIR] [--verbose]

Example:
    python collect_logs.py F.D4VBGUC6CVB76.H
    python collect_logs.py F.D4VBGUC6CVB76.H --config ./api.config.yaml --output ./logs
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2, api_pb2_grpc


class VelociraptorCollector:
    """Velociraptor client for collecting hunt artifacts"""

    # Artifacts to collect from each client
    ARTIFACTS = [
        "Custom.Linux.Listeners.List",
        "Custom.Linux.Process.List",
        "Custom.Linux.Sysmon.Collector",
        "Custom.Windows.Listeners.List",
        "Custom.Windows.Process.List",
        "Custom.Windows.Sysmon.Collector",
    ]

    def __init__(self, config_path: str, verbose: bool = False):
        """Initialize the collector with configuration"""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config_path = config_path
        self.verbose = verbose

        # Set logging level
        if verbose:
            self.logger.setLevel(logging.DEBUG)
            logging.getLogger().setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        # Load Velociraptor config
        self.config = pyvelociraptor.LoadConfigFile(config_path)

        # Set up SSL credentials
        self.creds = grpc.ssl_channel_credentials(
            root_certificates=self.config["ca_certificate"].encode("utf8"),
            private_key=self.config["client_private_key"].encode("utf8"),
            certificate_chain=self.config["client_cert"].encode("utf8"),
        )

        # Required option for self-signed certs
        self.options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)

        self.logger.info(f"Initialized with config: {config_path}")

    def execute_query(self, query: str, org_id: str = None, max_row: int = 10000) -> list:
        """Execute a VQL query and return results"""
        with grpc.secure_channel(
            self.config["api_connection_string"], self.creds, self.options
        ) as channel:
            stub = api_pb2_grpc.APIStub(channel)

            request = api_pb2.VQLCollectorArgs(
                org_id=org_id or "",
                max_wait=1,
                max_row=max_row,
                timeout=0,
                Query=[
                    api_pb2.VQLRequest(
                        Name="Collector Query",
                        VQL=query,
                    )
                ],
            )

            self.logger.debug(f"Executing: {query}")

            results = []
            for response in stub.Query(request):
                if response.Response:
                    package = json.loads(response.Response)
                    results.extend(package)

            return results

    def get_clients(self) -> dict:
        """Get all connected clients"""
        query = "SELECT * FROM clients()"
        clients = self.execute_query(query)

        # Build client_id -> hostname mapping
        client_map = {}
        for client in clients:
            if client.get("client_id"):
                hostname = client.get("os_info", {}).get("hostname", "unknown")
                client_map[client["client_id"]] = hostname

        self.logger.info(f"Found {len(client_map)} clients")
        return client_map

    def collect_hunt_artifacts(self, hunt_id: str, output_dir: Path) -> dict:
        """
        Collect all artifacts from a hunt

        Args:
            hunt_id: The Velociraptor hunt ID (e.g., F.D4VBGUC6CVB76.H)
            output_dir: Directory to save collected logs

        Returns:
            Summary dict with collection statistics
        """
        self.logger.info(f"Collecting artifacts from hunt: {hunt_id}")
        self.logger.info(f"Output directory: {output_dir}")

        # Get all clients
        clients = self.get_clients()

        if not clients:
            self.logger.error("No clients found!")
            return {"error": "No clients found"}

        summary = {
            "hunt_id": hunt_id,
            "clients_processed": 0,
            "artifacts_collected": 0,
            "total_records": 0,
            "details": {},
        }

        # Collect from each client
        for client_id, hostname in clients.items():
            self.logger.info(f"Processing: {hostname} ({client_id})")
            client_summary = {}

            for artifact in self.ARTIFACTS:
                query = f'SELECT * FROM source(artifact="{artifact}", client_id="{client_id}", flow_id="{hunt_id}")'

                try:
                    result = self.execute_query(query)
                except Exception as e:
                    self.logger.warning(f"  Failed to collect {artifact}: {e}")
                    continue

                if result:
                    # Create output file
                    filename = output_dir / hostname / f"{artifact.replace('.', '_')}.json"
                    filename.parent.mkdir(parents=True, exist_ok=True)

                    with open(filename, "w") as f:
                        json.dump(result, f, indent=2, default=str)

                    client_summary[artifact] = len(result)
                    summary["artifacts_collected"] += 1
                    summary["total_records"] += len(result)

                    self.logger.info(f"  ├── {artifact}: {len(result)} records")
                else:
                    self.logger.debug(f"  ├── {artifact}: 0 records (skipped)")

            if client_summary:
                summary["details"][hostname] = client_summary
                summary["clients_processed"] += 1

        self.logger.info("=" * 60)
        self.logger.info(f"Collection complete!")
        self.logger.info(f"  Clients processed: {summary['clients_processed']}")
        self.logger.info(f"  Artifacts collected: {summary['artifacts_collected']}")
        self.logger.info(f"  Total records: {summary['total_records']:,}")

        return summary


def main():
    parser = argparse.ArgumentParser(
        description="Collect forensic logs from Velociraptor hunt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s F.D4VBGUC6CVB76.H
    %(prog)s F.D4VBGUC6CVB76.H --config ./api.config.yaml
    %(prog)s F.D4VBGUC6CVB76.H --output ./collected_logs --verbose
        """,
    )

    parser.add_argument("hunt_id", help="Velociraptor hunt ID (e.g., F.D4VBGUC6CVB76.H)")

    parser.add_argument(
        "--config",
        "-c",
        default="./api.config.yaml",
        help="Path to Velociraptor API config file (default: ./api.config.yaml)",
    )

    parser.add_argument(
        "--output",
        "-o",
        default="./logs",
        help="Output directory for collected logs (default: ./logs)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Configure logging
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format=log_format, datefmt="%Y-%m-%d %H:%M:%S")

    # Validate config file exists
    config_path = Path(args.config)
    if not config_path.exists():
        logging.error(f"Config file not found: {config_path}")
        sys.exit(1)

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run collection
    try:
        collector = VelociraptorCollector(str(config_path), verbose=args.verbose)
        summary = collector.collect_hunt_artifacts(args.hunt_id, output_dir)

        # Save summary
        summary_file = output_dir / "collection_summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        logging.info(f"Summary saved to: {summary_file}")

    except Exception as e:
        logging.error(f"Collection failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
