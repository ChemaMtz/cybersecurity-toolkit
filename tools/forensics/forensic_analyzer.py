#!/usr/bin/env python3
"""
Advanced Digital Forensics Analysis Tool
=======================================
Enterprise digital forensics and incident response artifact collector,
system baseline extractor, registry inspector, log correlation and timeline generator.
"""

import os
import sys
import json
import hashlib
import datetime
import platform
import subprocess
import socket
import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path

# Safe Windows stdout reconfigure
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Optional third-party modules
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

# Windows registry access
if platform.system() == 'Windows':
    try:
        import winreg
        HAS_WINREG = True
    except ImportError:
        HAS_WINREG = False
else:
    HAS_WINREG = False

logger = logging.getLogger(__name__)


@dataclass
class ForensicArtifact:
    """Forensic artifact data model"""
    type: str
    source: str
    timestamp: str
    data: Dict[str, Any]
    hash: str
    severity: str  # 'low', 'medium', 'high', 'critical'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ForensicAnalyzer:
    """
    Advanced digital forensics analysis and artifact collector.
    """

    def __init__(self, evidence_dir: str = "forensic_evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(exist_ok=True)
        self.artifacts: List[ForensicArtifact] = []
        self.timeline: List[Dict[str, Any]] = []

    def collect_system_info(self) -> Dict[str, Any]:
        """Collect comprehensive operating system and hardware state"""
        boot_time_str = "Unknown"
        if HAS_PSUTIL:
            try:
                boot_time_str = datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
            except Exception:
                pass

        info = {
            'system': {
                'hostname': platform.node(),
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': sys.version,
                'boot_time': boot_time_str
            },
            'users': self._get_user_info(),
            'network': self._get_network_info(),
            'processes': self._get_process_info(),
            'services': self._get_service_info()
        }
        return info

    def _get_user_info(self) -> List[Dict[str, Any]]:
        """Get user account details"""
        users = []
        if platform.system() != 'Windows':
            try:
                import pwd
                for user in pwd.getpwall():
                    users.append({
                        'username': user.pw_name,
                        'uid': user.pw_uid,
                        'gid': user.pw_gid,
                        'home': user.pw_dir,
                        'shell': user.pw_shell
                    })
                return users
            except Exception:
                pass

        # Windows / Fallback
        import getpass
        users.append({
            'username': getpass.getuser(),
            'home': os.path.expanduser('~')
        })
        return users

    def _get_network_info(self) -> List[Dict[str, Any]]:
        """Collect active socket connections and listening ports"""
        connections = []
        if HAS_PSUTIL:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid,
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    })
            except Exception as e:
                logger.debug(f"Network connections error: {e}")
        return connections

    def _get_process_info(self) -> List[Dict[str, Any]]:
        """Collect running processes and command lines"""
        processes = []
        if HAS_PSUTIL:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time', 'cmdline']):
                    try:
                        pinfo = proc.info
                        processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'user': pinfo['username'],
                            'start_time': datetime.datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo['create_time'] else '',
                            'command': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ''
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception as e:
                logger.debug(f"Process collection error: {e}")
        return processes

    def _get_service_info(self) -> List[Dict[str, Any]]:
        """Collect installed service status"""
        services = []
        if platform.system() == 'Windows':
            try:
                # Use standard Windows PowerShell or sc command fallback
                cmd = ["powershell", "-Command", "Get-Service | Select-Object -First 20 Name, Status, DisplayName | ConvertTo-Json"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0 and res.stdout.strip():
                    raw_data = json.loads(res.stdout)
                    if isinstance(raw_data, list):
                        for item in raw_data:
                            services.append({
                                'name': item.get('Name'),
                                'display_name': item.get('DisplayName'),
                                'status': item.get('Status')
                            })
            except Exception:
                pass
        return services

    def analyze_logs(self, log_dir: Optional[str] = None) -> List[ForensicArtifact]:
        """Analyze system logs for indicators of compromise (IOCs)"""
        artifacts = []
        suspicious_patterns = [
            (r'failed password', 'Authentication Failure', 'high'),
            (r'session opened', 'New Session', 'low'),
            (r'sudo:', 'Sudo Command Executed', 'medium'),
            (r'segfault', 'Application Memory Crash', 'medium'),
            (r'permission denied', 'Access Violation', 'medium'),
            (r'error', 'System Error Condition', 'low')
        ]

        target_dir = log_dir or ("/var/log" if platform.system() != 'Windows' else os.environ.get("TEMP", "."))
        log_path = Path(target_dir)

        if log_path.exists():
            for log_file in list(log_path.glob('*.log'))[:10]:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            for pattern, artifact_type, sev in suspicious_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    artifact = ForensicArtifact(
                                        type=artifact_type,
                                        source=str(log_file),
                                        timestamp=datetime.datetime.now().isoformat(),
                                        data={'line': line.strip()[:200]},
                                        hash=hashlib.md5(line.encode()).hexdigest(),
                                        severity=sev
                                    )
                                    artifacts.append(artifact)
                except Exception:
                    pass

        return artifacts

    def analyze_registry(self) -> List[ForensicArtifact]:
        """Analyze Windows Registry persistence mechanisms (Run, RunOnce, Services)"""
        artifacts = []
        if not HAS_WINREG:
            return artifacts

        suspicious_keys = [
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'Auto-start Entry', winreg.HKEY_LOCAL_MACHINE),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'Auto-start Entry', winreg.HKEY_LOCAL_MACHINE),
            (r'Software\Microsoft\Windows\CurrentVersion\Run', 'User Auto-start Entry', winreg.HKEY_CURRENT_USER),
        ]

        for key_path, artifact_type, root_hive in suspicious_keys:
            try:
                key = winreg.OpenKey(root_hive, key_path, 0, winreg.KEY_READ)
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    name, value, _ = winreg.EnumValue(key, i)
                    artifact = ForensicArtifact(
                        type=artifact_type,
                        source=f"Registry: {key_path}",
                        timestamp=datetime.datetime.now().isoformat(),
                        data={'name': name, 'value': str(value)},
                        hash=hashlib.md5(f"{key_path}{name}{value}".encode()).hexdigest(),
                        severity='high'
                    )
                    artifacts.append(artifact)
                winreg.CloseKey(key)
            except Exception:
                pass

        return artifacts

    def analyze_file_system(self, start_path: Optional[str] = None) -> List[ForensicArtifact]:
        """Analyze file system for suspicious directories and script extensions"""
        artifacts = []
        suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.sh', '.php', '.pcap']
        suspicious_dir_names = ['temp', 'tmp', 'download', 'appdata', 'startup', 'hidden']

        root_search = start_path or (os.environ.get("TEMP", ".") if platform.system() == 'Windows' else "/tmp")

        try:
            for root, dirs, files in os.walk(root_search):
                for dir_name in dirs:
                    if any(s in dir_name.lower() for s in suspicious_dir_names):
                        artifacts.append(ForensicArtifact(
                            type='Suspicious Directory Path',
                            source=os.path.join(root, dir_name),
                            timestamp=datetime.datetime.now().isoformat(),
                            data={'directory': dir_name},
                            hash=hashlib.md5(dir_name.encode()).hexdigest(),
                            severity='medium'
                        ))

                for file_name in files:
                    ext = Path(file_name).suffix.lower()
                    if ext in suspicious_extensions:
                        file_path = os.path.join(root, file_name)
                        try:
                            st = os.stat(file_path)
                            artifacts.append(ForensicArtifact(
                                type='Executable / Script File Artifact',
                                source=file_path,
                                timestamp=datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
                                data={
                                    'size': st.st_size,
                                    'extension': ext,
                                    'permissions': oct(st.st_mode)
                                },
                                hash=hashlib.md5(file_path.encode()).hexdigest(),
                                severity='low'
                            ))
                        except Exception:
                            pass

                # Limit depth for performance
                if len(artifacts) >= 50:
                    break
        except Exception:
            pass

        return artifacts

    def generate_report(self, output_file: str = "forensic_report.json") -> Dict[str, Any]:
        """Generate comprehensive forensic triage report"""
        if HAS_RICH and console:
            console.print(Panel("🔍 Starting Digital Forensics Analysis & Triage", style="bold red"))

        system_info = self.collect_system_info()
        log_artifacts = self.analyze_logs()
        registry_artifacts = self.analyze_registry()
        fs_artifacts = self.analyze_file_system()

        all_artifacts = log_artifacts + registry_artifacts + fs_artifacts
        total_artifacts = len(all_artifacts)

        severity_summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for a in all_artifacts:
            sev = a.severity.lower()
            if sev in severity_summary:
                severity_summary[sev] += 1

        report = {
            'analysis_timestamp': datetime.datetime.now().isoformat(),
            'analyst': os.getenv('USERNAME') or os.getenv('USER', 'Analyst'),
            'system_info': system_info,
            'statistics': {
                'total_artifacts': total_artifacts,
                'log_artifacts': len(log_artifacts),
                'registry_artifacts': len(registry_artifacts),
                'filesystem_artifacts': len(fs_artifacts),
                'severity_breakdown': severity_summary
            },
            'log_artifacts': [a.to_dict() for a in log_artifacts],
            'registry_artifacts': [a.to_dict() for a in registry_artifacts],
            'filesystem_artifacts': [a.to_dict() for a in fs_artifacts]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        if HAS_RICH and console:
            table = Table(title="Forensic Analysis Summary")
            table.add_column("Category", style="cyan")
            table.add_column("Artifacts Extracted", style="magenta")
            table.add_column("Status", style="green")

            table.add_row("System Logs", str(len(log_artifacts)), "Completed")
            table.add_row("Registry / Persistence", str(len(registry_artifacts)), "Completed")
            table.add_row("File System", str(len(fs_artifacts)), "Completed")
            table.add_row("Total Triage Artifacts", str(total_artifacts), "Report Ready")
            console.print(table)
            console.print(f"[+] Forensic report saved to: [bold green]{output_file}[/bold green]")
        else:
            print("=" * 65)
            print(f"[*] Forensic Report Generated: {output_file}")
            print(f"[*] Total Artifacts: {total_artifacts}")
            print(f"  - Logs: {len(log_artifacts)} | Registry: {len(registry_artifacts)} | FileSystem: {len(fs_artifacts)}")
            print("=" * 65)

        return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Digital Forensics Analysis Tool.")
    parser.add_argument("-o", "--output", default="forensic_report.json", help="Path to output JSON report")
    args = parser.parse_args()

    analyzer = ForensicAnalyzer()
    analyzer.generate_report(output_file=args.output)


if __name__ == "__main__":
    main()
