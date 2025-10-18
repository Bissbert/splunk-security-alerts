# Security Tools Integration Guide

## Table of Contents
1. [Integration Architecture](#integration-architecture)
2. [SIEM Integration](#siem-integration)
3. [SOAR Platform Integration](#soar-platform-integration)
4. [Ticketing System Integration](#ticketing-system-integration)
5. [Threat Intelligence Platforms](#threat-intelligence-platforms)
6. [EDR/XDR Integration](#edrxdr-integration)
7. [Cloud Security Integration](#cloud-security-integration)
8. [Network Security Tools](#network-security-tools)
9. [Communication Platforms](#communication-platforms)
10. [API Reference](#api-reference)
11. [Webhook Configuration](#webhook-configuration)
12. [Data Format Standards](#data-format-standards)

---

## Integration Architecture

### High-Level Integration Overview

```mermaid
flowchart TB
    subgraph SplunkCore["Splunk Platform"]
        Alerts["Alert Engine"]
        API["REST API"]
        HEC["HTTP Event Collector"]
        Forwarders["Universal Forwarders"]
    end

    subgraph SIEM["SIEM/SOAR"]
        ESM["Enterprise Security"]
        SOAR["SOAR Platform"]
        TIP["Threat Intel Platform"]
    end

    subgraph ITTools["IT Service Management"]
        Ticketing["ServiceNow/JIRA"]
        CMDB["Configuration DB"]
        Monitoring["Infrastructure Monitoring"]
    end

    subgraph SecTools["Security Tools"]
        EDR["EDR/XDR Solutions"]
        Firewall["Firewalls/IPS"]
        Proxy["Web Proxies"]
        DLP["DLP Solutions"]
    end

    subgraph Comms["Communications"]
        Email["Email Gateway"]
        Slack["Slack/Teams"]
        Pager["PagerDuty"]
    end

    %% Data flows
    Alerts --> API
    API <--> SOAR
    API <--> Ticketing
    API --> Slack
    API --> Pager

    EDR --> HEC
    Firewall --> Forwarders
    Proxy --> Forwarders
    DLP --> HEC

    TIP <--> API
    ESM <--> API
    CMDB --> API

    Monitoring --> HEC
    Email <--> API
```

### Integration Data Flow

```mermaid
sequenceDiagram
    participant Splunk
    participant Webhook
    participant SOAR
    participant Ticket
    participant Analyst

    Splunk->>Webhook: Alert Triggered
    Webhook->>SOAR: Create Playbook
    SOAR->>Ticket: Open Incident
    Ticket->>Analyst: Assign Task

    Analyst->>Ticket: Update Status
    Ticket->>SOAR: Status Change
    SOAR->>Splunk: Update Alert
    Splunk->>Webhook: Close Loop
```

---

## SIEM Integration

### Splunk Enterprise Security Integration

#### Configuration Setup

```python
#!/usr/bin/env python3
import requests
import json
from datetime import datetime

class SplunkESIntegration:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.auth = (username, password)
        self.headers = {'Content-Type': 'application/json'}

    def create_notable_event(self, alert_data):
        """Create a notable event in Splunk ES"""

        notable = {
            'rule_name': alert_data.get('alert_name'),
            'rule_title': alert_data.get('alert_title'),
            'rule_description': alert_data.get('description'),
            'security_domain': self.map_security_domain(alert_data),
            'severity': self.map_severity(alert_data.get('severity')),
            'owner': alert_data.get('assigned_to', 'unassigned'),
            'status': '1',  # New
            'urgency': self.calculate_urgency(alert_data),
            'event_id': alert_data.get('event_id'),
            'src_ip': alert_data.get('src_ip'),
            'dest_ip': alert_data.get('dest_ip'),
            'user': alert_data.get('user'),
            'time': alert_data.get('_time', datetime.now().timestamp())
        }

        endpoint = f"{self.base_url}/services/notable_update"

        response = requests.post(
            endpoint,
            auth=self.auth,
            headers=self.headers,
            data=json.dumps(notable)
        )

        return response.json()

    def map_security_domain(self, alert_data):
        """Map alert to ES security domain"""
        mapping = {
            'Unauthorized SSH Access': 'access',
            'Data Exfiltration': 'threat',
            'Privilege Escalation': 'identity',
            'Lateral Movement': 'threat',
            'Port Scanning': 'network',
            'Suspicious Process': 'endpoint'
        }
        return mapping.get(alert_data.get('alert_name'), 'threat')

    def map_severity(self, severity):
        """Map severity to ES scale"""
        mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'informational': 'informational'
        }
        return mapping.get(severity.lower(), 'unknown')

    def calculate_urgency(self, alert_data):
        """Calculate urgency based on various factors"""
        urgency_score = 50  # Base score

        # Adjust based on severity
        severity_scores = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10
        }
        urgency_score += severity_scores.get(alert_data.get('severity', '').lower(), 0)

        # Adjust based on asset criticality
        if alert_data.get('asset_criticality') == 'critical':
            urgency_score += 10

        # Adjust based on user privilege
        if alert_data.get('user_privilege') == 'admin':
            urgency_score += 10

        return min(urgency_score, 100)  # Cap at 100

    def update_risk_score(self, object_type, object_name, risk_score):
        """Update risk score for an object"""

        risk_data = {
            'risk_object_type': object_type,  # user, system, etc.
            'risk_object': object_name,
            'risk_score': risk_score,
            'risk_message': f"Risk score updated via integration: {risk_score}"
        }

        endpoint = f"{self.base_url}/services/risks/update"

        response = requests.post(
            endpoint,
            auth=self.auth,
            headers=self.headers,
            data=json.dumps(risk_data)
        )

        return response.status_code == 200

# Usage
es_integration = SplunkESIntegration(
    'https://splunk-es.example.com:8089',
    'admin',
    'password'
)

alert_data = {
    'alert_name': 'Unauthorized SSH Access',
    'severity': 'critical',
    'src_ip': '192.168.1.100',
    'user': 'john.doe',
    'asset_criticality': 'critical'
}

notable = es_integration.create_notable_event(alert_data)
print(f"Created notable event: {notable}")
```

### Integration with QRadar

```python
#!/usr/bin/env python3
import requests
import json
from base64 import b64encode

class QRadarIntegration:
    def __init__(self, console_url, api_token):
        self.console_url = console_url
        self.headers = {
            'SEC': api_token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def send_event(self, splunk_alert):
        """Send Splunk alert to QRadar as event"""

        # Convert Splunk alert to LEEF format
        leef_event = self.convert_to_leef(splunk_alert)

        endpoint = f"{self.console_url}/api/data_input/events"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=leef_event
        )

        return response.status_code == 201

    def convert_to_leef(self, alert):
        """Convert Splunk alert to LEEF format"""

        leef = f"LEEF:2.0|Splunk|SecurityAlerts|1.0|{alert['alert_name']}|"

        # Add key-value pairs
        fields = {
            'devTime': alert.get('_time'),
            'severity': self.map_severity(alert.get('severity')),
            'src': alert.get('src_ip'),
            'dst': alert.get('dest_ip'),
            'usrName': alert.get('user'),
            'action': alert.get('action', 'alert'),
            'message': alert.get('description')
        }

        leef += '|'.join([f"{k}={v}" for k, v in fields.items() if v])

        return leef

    def map_severity(self, splunk_severity):
        """Map Splunk severity to QRadar scale (1-10)"""
        mapping = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'informational': 1
        }
        return mapping.get(splunk_severity.lower(), 5)

    def create_offense(self, alert_data):
        """Create offense in QRadar"""

        offense_data = {
            'description': alert_data.get('description'),
            'offense_type': self.map_offense_type(alert_data),
            'severity': self.map_severity(alert_data.get('severity')),
            'credibility': 3,  # Default credibility
            'relevance': 5,   # Default relevance
            'assigned_to': alert_data.get('assigned_to')
        }

        endpoint = f"{self.console_url}/api/siem/offenses"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps(offense_data)
        )

        return response.json()

    def map_offense_type(self, alert_data):
        """Map alert to QRadar offense type"""
        mapping = {
            'Unauthorized SSH Access': 'Authentication',
            'Data Exfiltration': 'DataLoss',
            'Privilege Escalation': 'Exploitation',
            'Lateral Movement': 'Malware',
            'Port Scanning': 'Recon'
        }
        return mapping.get(alert_data.get('alert_name'), 'Other')

# Usage
qradar = QRadarIntegration(
    'https://qradar.example.com',
    'YOUR_API_TOKEN'
)

alert = {
    'alert_name': 'Data Exfiltration',
    'severity': 'high',
    'src_ip': '10.0.0.100',
    'dest_ip': '203.0.113.0',
    'description': 'Large data transfer to external IP'
}

qradar.send_event(alert)
offense = qradar.create_offense(alert)
print(f"Created QRadar offense: {offense}")
```

---

## SOAR Platform Integration

### Integration with Phantom/SOAR

```python
#!/usr/bin/env python3
import requests
import json
from datetime import datetime

class PhantomSOARIntegration:
    def __init__(self, phantom_url, auth_token):
        self.phantom_url = phantom_url
        self.headers = {
            'ph-auth-token': auth_token,
            'Content-Type': 'application/json'
        }

    def create_container(self, alert_data):
        """Create a container (incident) in Phantom"""

        container = {
            'name': alert_data.get('alert_name'),
            'description': alert_data.get('description'),
            'label': 'splunk_alert',
            'severity': alert_data.get('severity', 'medium'),
            'status': 'new',
            'start_time': datetime.now().isoformat(),
            'source_data_identifier': alert_data.get('event_id'),
            'custom_fields': {
                'splunk_search_id': alert_data.get('search_id'),
                'splunk_index': alert_data.get('index'),
                'alert_time': alert_data.get('_time')
            }
        }

        endpoint = f"{self.phantom_url}/rest/container"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps(container)
        )

        return response.json()

    def add_artifact(self, container_id, artifact_data):
        """Add artifact to container"""

        artifact = {
            'container_id': container_id,
            'name': artifact_data.get('name'),
            'label': artifact_data.get('type', 'event'),
            'severity': artifact_data.get('severity', 'medium'),
            'cef': artifact_data.get('cef', {}),
            'source_data_identifier': artifact_data.get('source_id')
        }

        endpoint = f"{self.phantom_url}/rest/artifact"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps(artifact)
        )

        return response.json()

    def run_playbook(self, container_id, playbook_name):
        """Execute a playbook on container"""

        playbook_run = {
            'container_id': container_id,
            'playbook_name': playbook_name,
            'scope': 'new',
            'run': True
        }

        endpoint = f"{self.phantom_url}/rest/playbook_run"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps(playbook_run)
        )

        return response.json()

    def map_alert_to_playbook(self, alert_name):
        """Map Splunk alert to appropriate playbook"""

        playbook_mapping = {
            'Unauthorized SSH Access': 'ssh_incident_response',
            'Data Exfiltration': 'data_loss_prevention',
            'Privilege Escalation': 'privilege_escalation_response',
            'Lateral Movement': 'lateral_movement_containment',
            'Port Scanning': 'reconnaissance_response',
            'Suspicious Process': 'endpoint_investigation',
            'Failed Authentication Spike': 'brute_force_response',
            'Command and Control Beacon': 'c2_investigation',
            'Account Manipulation': 'account_security_response',
            'File Integrity Violation': 'file_integrity_response'
        }

        return playbook_mapping.get(alert_name, 'generic_investigation')

    def create_incident_from_alert(self, alert_data):
        """Complete workflow to create and process incident"""

        # Create container
        container = self.create_container(alert_data)
        container_id = container.get('id')

        # Add artifacts
        artifacts = [
            {
                'name': 'Source IP',
                'type': 'ip',
                'cef': {'sourceAddress': alert_data.get('src_ip')}
            },
            {
                'name': 'Destination IP',
                'type': 'ip',
                'cef': {'destinationAddress': alert_data.get('dest_ip')}
            },
            {
                'name': 'User',
                'type': 'user',
                'cef': {'sourceUserName': alert_data.get('user')}
            }
        ]

        for artifact in artifacts:
            if artifact['cef']:
                self.add_artifact(container_id, artifact)

        # Run appropriate playbook
        playbook = self.map_alert_to_playbook(alert_data.get('alert_name'))
        playbook_run = self.run_playbook(container_id, playbook)

        return {
            'container_id': container_id,
            'playbook_run_id': playbook_run.get('id'),
            'status': 'created'
        }

# Usage
phantom = PhantomSOARIntegration(
    'https://phantom.example.com',
    'YOUR_AUTH_TOKEN'
)

alert_data = {
    'alert_name': 'Lateral Movement Detected',
    'description': 'Multiple authentication attempts across systems',
    'severity': 'high',
    'src_ip': '192.168.1.50',
    'dest_ip': '192.168.1.100',
    'user': 'suspicious_user',
    'event_id': 'EVT123456'
}

incident = phantom.create_incident_from_alert(alert_data)
print(f"Created Phantom incident: {incident}")
```

### Integration with Cortex XSOAR

```python
#!/usr/bin/env python3
import requests
import json
from typing import Dict, List, Any

class CortexXSOARIntegration:
    def __init__(self, server_url: str, api_key: str):
        self.server_url = server_url
        self.headers = {
            'Authorization': api_key,
            'Content-Type': 'application/json'
        }

    def create_incident(self, alert_data: Dict[str, Any]) -> Dict:
        """Create incident in Cortex XSOAR"""

        incident = {
            'name': alert_data.get('alert_name'),
            'type': self.map_incident_type(alert_data),
            'severity': self.map_severity(alert_data.get('severity')),
            'details': alert_data.get('description'),
            'occurred': alert_data.get('_time'),
            'CustomFields': {
                'splunkalertid': alert_data.get('alert_id'),
                'sourceip': alert_data.get('src_ip'),
                'destinationip': alert_data.get('dest_ip'),
                'affecteduser': alert_data.get('user'),
                'alertsource': 'Splunk'
            },
            'labels': self.generate_labels(alert_data)
        }

        endpoint = f"{self.server_url}/incident"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps({'incident': incident})
        )

        return response.json()

    def map_incident_type(self, alert_data: Dict) -> str:
        """Map alert to XSOAR incident type"""
        mapping = {
            'Unauthorized SSH Access': 'Authentication',
            'Data Exfiltration': 'Data Breach',
            'Privilege Escalation': 'Privilege Escalation',
            'Lateral Movement': 'Lateral Movement',
            'Port Scanning': 'Reconnaissance',
            'Suspicious Process': 'Malware',
            'C2 Beacon': 'Command and Control'
        }
        return mapping.get(alert_data.get('alert_name'), 'Unclassified')

    def map_severity(self, severity: str) -> int:
        """Map severity to XSOAR scale (0-4)"""
        mapping = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'informational': 0
        }
        return mapping.get(severity.lower(), 1)

    def generate_labels(self, alert_data: Dict) -> List[Dict]:
        """Generate incident labels"""
        labels = []

        if alert_data.get('src_ip'):
            labels.append({
                'type': 'Source IP',
                'value': alert_data.get('src_ip')
            })

        if alert_data.get('user'):
            labels.append({
                'type': 'User',
                'value': alert_data.get('user')
            })

        if alert_data.get('mitre_technique'):
            labels.append({
                'type': 'MITRE ATT&CK',
                'value': alert_data.get('mitre_technique')
            })

        return labels

    def run_playbook(self, incident_id: str, playbook_name: str) -> Dict:
        """Run a playbook on an incident"""

        playbook_data = {
            'incidentId': incident_id,
            'playbookName': playbook_name
        }

        endpoint = f"{self.server_url}/playbook/run"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps(playbook_data)
        )

        return response.json()

    def add_entry(self, incident_id: str, entry_data: Dict) -> Dict:
        """Add investigation entry to incident"""

        entry = {
            'id': incident_id,
            'investigationId': incident_id,
            'data': entry_data.get('data'),
            'markdown': entry_data.get('markdown', True),
            'tags': entry_data.get('tags', [])
        }

        endpoint = f"{self.server_url}/entry"

        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps(entry)
        )

        return response.json()

# Usage
xsoar = CortexXSOARIntegration(
    'https://xsoar.example.com',
    'YOUR_API_KEY'
)

alert = {
    'alert_name': 'Data Exfiltration',
    'severity': 'critical',
    'src_ip': '10.0.0.50',
    'dest_ip': '198.51.100.1',
    'user': 'john.doe',
    'description': 'Large data transfer detected to unknown external IP',
    'mitre_technique': 'T1048'
}

incident = xsoar.create_incident(alert)
print(f"Created XSOAR incident: {incident}")
```

---

## Ticketing System Integration

### ServiceNow Integration

```python
#!/usr/bin/env python3
import requests
import json
from datetime import datetime

class ServiceNowIntegration:
    def __init__(self, instance_url, username, password):
        self.instance_url = instance_url
        self.auth = (username, password)
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def create_incident(self, alert_data):
        """Create ServiceNow incident from Splunk alert"""

        incident = {
            'short_description': alert_data.get('alert_name'),
            'description': self.format_description(alert_data),
            'category': 'Security',
            'subcategory': self.map_subcategory(alert_data),
            'impact': self.map_impact(alert_data.get('severity')),
            'urgency': self.map_urgency(alert_data.get('severity')),
            'assignment_group': 'Security Operations',
            'caller_id': 'splunk_integration',
            'u_detection_source': 'Splunk',
            'u_alert_id': alert_data.get('alert_id'),
            'u_source_ip': alert_data.get('src_ip'),
            'u_destination_ip': alert_data.get('dest_ip'),
            'u_affected_user': alert_data.get('user'),
            'work_notes': self.generate_work_notes(alert_data)
        }

        endpoint = f"{self.instance_url}/api/now/table/incident"

        response = requests.post(
            endpoint,
            auth=self.auth,
            headers=self.headers,
            data=json.dumps(incident)
        )

        return response.json()

    def format_description(self, alert_data):
        """Format detailed description for incident"""

        description = f"""
        Alert Name: {alert_data.get('alert_name')}
        Severity: {alert_data.get('severity')}
        Time: {alert_data.get('_time')}

        Details:
        {alert_data.get('description')}

        Affected Resources:
        - Source IP: {alert_data.get('src_ip')}
        - Destination IP: {alert_data.get('dest_ip')}
        - User: {alert_data.get('user')}
        - Host: {alert_data.get('host')}

        Additional Context:
        {alert_data.get('context', 'N/A')}

        Splunk Search:
        {alert_data.get('search_query', 'N/A')}
        """

        return description

    def map_subcategory(self, alert_data):
        """Map alert to ServiceNow subcategory"""
        mapping = {
            'Unauthorized SSH Access': 'Unauthorized Access',
            'Data Exfiltration': 'Data Loss',
            'Privilege Escalation': 'Privilege Abuse',
            'Lateral Movement': 'Malicious Activity',
            'Port Scanning': 'Reconnaissance'
        }
        return mapping.get(alert_data.get('alert_name'), 'Security Incident')

    def map_impact(self, severity):
        """Map severity to ServiceNow impact (1-3)"""
        mapping = {
            'critical': 1,  # High
            'high': 2,      # Medium
            'medium': 2,    # Medium
            'low': 3        # Low
        }
        return mapping.get(severity.lower(), 3)

    def map_urgency(self, severity):
        """Map severity to ServiceNow urgency (1-3)"""
        mapping = {
            'critical': 1,  # High
            'high': 1,      # High
            'medium': 2,    # Medium
            'low': 3        # Low
        }
        return mapping.get(severity.lower(), 3)

    def generate_work_notes(self, alert_data):
        """Generate initial work notes"""

        notes = f"""
        === Automated Security Alert ===
        Generated by Splunk Security Monitoring

        Initial Assessment Required:
        1. Verify the alert details
        2. Check for false positive indicators
        3. Assess impact on business operations
        4. Determine if immediate action is required

        Recommended Actions:
        """

        # Add specific recommendations based on alert type
        if alert_data.get('alert_name') == 'Unauthorized SSH Access':
            notes += """
        - Verify if the source IP is legitimate
        - Check if the user account is compromised
        - Review SSH logs for additional suspicious activity
        - Consider blocking the source IP if malicious
            """
        elif alert_data.get('alert_name') == 'Data Exfiltration':
            notes += """
        - Identify the data that was potentially exfiltrated
        - Block communication to the destination IP
        - Check for other systems communicating with the same destination
        - Initiate data breach response procedures if confirmed
            """

        return notes

    def update_incident(self, incident_id, update_data):
        """Update existing ServiceNow incident"""

        endpoint = f"{self.instance_url}/api/now/table/incident/{incident_id}"

        response = requests.patch(
            endpoint,
            auth=self.auth,
            headers=self.headers,
            data=json.dumps(update_data)
        )

        return response.json()

    def add_attachment(self, incident_id, file_path, file_name):
        """Add attachment to incident"""

        endpoint = f"{self.instance_url}/api/now/attachment/file"

        params = {
            'table_name': 'incident',
            'table_sys_id': incident_id,
            'file_name': file_name
        }

        with open(file_path, 'rb') as f:
            response = requests.post(
                endpoint,
                auth=self.auth,
                params=params,
                headers={'Content-Type': 'application/octet-stream'},
                data=f
            )

        return response.json()

# Usage
snow = ServiceNowIntegration(
    'https://instance.service-now.com',
    'username',
    'password'
)

alert_data = {
    'alert_name': 'Data Exfiltration Attempt',
    'severity': 'critical',
    'src_ip': '10.0.0.100',
    'dest_ip': '198.51.100.1',
    'user': 'compromised_user',
    'description': 'Large volume of data transferred to external IP',
    'alert_id': 'ALERT-12345'
}

incident = snow.create_incident(alert_data)
print(f"Created ServiceNow incident: {incident}")
```

### JIRA Integration

```python
#!/usr/bin/env python3
from jira import JIRA
import json
from datetime import datetime

class JiraIntegration:
    def __init__(self, server_url, username, api_token):
        self.jira = JIRA(
            server=server_url,
            basic_auth=(username, api_token)
        )
        self.project_key = 'SEC'  # Security project

    def create_issue(self, alert_data):
        """Create JIRA issue from Splunk alert"""

        issue_dict = {
            'project': {'key': self.project_key},
            'summary': f"[{alert_data.get('severity').upper()}] {alert_data.get('alert_name')}",
            'description': self.format_description(alert_data),
            'issuetype': {'name': self.map_issue_type(alert_data)},
            'priority': {'name': self.map_priority(alert_data.get('severity'))},
            'labels': self.generate_labels(alert_data),
            'customfield_10001': alert_data.get('alert_id'),  # Alert ID field
            'customfield_10002': alert_data.get('src_ip'),    # Source IP field
            'customfield_10003': alert_data.get('dest_ip'),   # Dest IP field
            'components': [{'name': 'Security Monitoring'}]
        }

        issue = self.jira.create_issue(fields=issue_dict)
        return issue

    def format_description(self, alert_data):
        """Format JIRA description with formatting"""

        description = f"""
h3. Alert Details
||Field||Value||
|Alert Name|{alert_data.get('alert_name')}|
|Severity|{alert_data.get('severity')}|
|Time|{alert_data.get('_time')}|
|Source IP|{alert_data.get('src_ip')}|
|Destination IP|{alert_data.get('dest_ip')}|
|User|{alert_data.get('user')}|
|Host|{alert_data.get('host')}|

h3. Description
{alert_data.get('description')}

h3. Investigation Steps
# Verify the alert details in Splunk
# Check for related alerts in the same timeframe
# Identify if this is a false positive
# Assess the impact on affected systems
# Determine appropriate response actions

h3. Splunk Query
{{code}}
{alert_data.get('search_query', 'N/A')}
{{code}}

h3. Additional Context
{alert_data.get('context', 'No additional context available')}
        """

        return description

    def map_issue_type(self, alert_data):
        """Map alert to JIRA issue type"""
        if alert_data.get('severity') in ['critical', 'high']:
            return 'Security Incident'
        else:
            return 'Security Alert'

    def map_priority(self, severity):
        """Map severity to JIRA priority"""
        mapping = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'informational': 'Lowest'
        }
        return mapping.get(severity.lower(), 'Medium')

    def generate_labels(self, alert_data):
        """Generate JIRA labels"""
        labels = ['splunk', 'security-alert']

        # Add severity label
        labels.append(f"severity-{alert_data.get('severity', 'unknown')}")

        # Add alert type label
        alert_type = alert_data.get('alert_name', '').replace(' ', '-').lower()
        labels.append(alert_type)

        # Add MITRE technique if available
        if alert_data.get('mitre_technique'):
            labels.append(alert_data.get('mitre_technique'))

        return labels

    def update_issue(self, issue_key, update_data):
        """Update existing JIRA issue"""
        issue = self.jira.issue(issue_key)
        issue.update(fields=update_data)
        return issue

    def add_comment(self, issue_key, comment_text):
        """Add comment to JIRA issue"""
        issue = self.jira.issue(issue_key)
        self.jira.add_comment(issue, comment_text)

    def transition_issue(self, issue_key, transition_name):
        """Transition issue to different status"""
        issue = self.jira.issue(issue_key)
        transitions = self.jira.transitions(issue)

        # Find transition ID by name
        transition_id = None
        for transition in transitions:
            if transition['name'] == transition_name:
                transition_id = transition['id']
                break

        if transition_id:
            self.jira.transition_issue(issue, transition_id)

    def attach_file(self, issue_key, file_path, file_name):
        """Attach file to JIRA issue"""
        issue = self.jira.issue(issue_key)
        with open(file_path, 'rb') as f:
            self.jira.add_attachment(issue, f, file_name)

# Usage
jira_integration = JiraIntegration(
    'https://company.atlassian.net',
    'user@example.com',
    'API_TOKEN'
)

alert_data = {
    'alert_name': 'Privilege Escalation Detected',
    'severity': 'high',
    'src_ip': '192.168.1.100',
    'user': 'standard_user',
    'description': 'User attempted to escalate privileges using sudo',
    'alert_id': 'SPL-2024-001',
    'mitre_technique': 'T1068'
}

issue = jira_integration.create_issue(alert_data)
print(f"Created JIRA issue: {issue.key}")
```

---

## Threat Intelligence Platforms

### MISP Integration

```python
#!/usr/bin/env python3
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
import json
from datetime import datetime

class MISPIntegration:
    def __init__(self, misp_url, api_key, verify_ssl=True):
        self.misp = ExpandedPyMISP(misp_url, api_key, verify_ssl)

    def create_event_from_alert(self, alert_data):
        """Create MISP event from Splunk alert"""

        event = MISPEvent()
        event.info = f"Splunk Alert: {alert_data.get('alert_name')}"
        event.distribution = 0  # Organization only
        event.threat_level_id = self.map_threat_level(alert_data.get('severity'))
        event.analysis = 1  # Ongoing

        # Add attributes
        if alert_data.get('src_ip'):
            event.add_attribute(
                'ip-src',
                alert_data.get('src_ip'),
                comment='Source IP from Splunk alert'
            )

        if alert_data.get('dest_ip'):
            event.add_attribute(
                'ip-dst',
                alert_data.get('dest_ip'),
                comment='Destination IP from Splunk alert'
            )

        if alert_data.get('domain'):
            event.add_attribute(
                'domain',
                alert_data.get('domain'),
                comment='Associated domain'
            )

        if alert_data.get('file_hash'):
            event.add_attribute(
                'sha256',
                alert_data.get('file_hash'),
                comment='File hash from alert'
            )

        # Add tags
        event.add_tag('splunk')
        event.add_tag(f"severity:{alert_data.get('severity')}")

        if alert_data.get('mitre_technique'):
            event.add_tag(f"mitre-attack-technique:{alert_data.get('mitre_technique')}")

        # Create event in MISP
        result = self.misp.add_event(event)
        return result

    def map_threat_level(self, severity):
        """Map Splunk severity to MISP threat level"""
        mapping = {
            'critical': 1,  # High
            'high': 2,      # Medium
            'medium': 3,    # Low
            'low': 4        # Undefined
        }
        return mapping.get(severity.lower(), 4)

    def search_ioc(self, value, type='ip-src'):
        """Search for IOC in MISP"""
        result = self.misp.search(
            controller='attributes',
            type_attribute=type,
            value=value,
            pythonify=True
        )
        return result

    def enrich_alert(self, alert_data):
        """Enrich Splunk alert with MISP threat intelligence"""

        enrichment = {
            'threat_intel': [],
            'related_events': [],
            'tags': []
        }

        # Search for source IP
        if alert_data.get('src_ip'):
            results = self.search_ioc(alert_data.get('src_ip'), 'ip-src')
            for attr in results:
                enrichment['threat_intel'].append({
                    'type': 'ip-src',
                    'value': attr.value,
                    'event_id': attr.event_id,
                    'tags': [tag.name for tag in attr.tags]
                })

        # Search for destination IP
        if alert_data.get('dest_ip'):
            results = self.search_ioc(alert_data.get('dest_ip'), 'ip-dst')
            for attr in results:
                enrichment['threat_intel'].append({
                    'type': 'ip-dst',
                    'value': attr.value,
                    'event_id': attr.event_id,
                    'tags': [tag.name for tag in attr.tags]
                })

        return enrichment

# Usage
misp = MISPIntegration(
    'https://misp.example.com',
    'YOUR_API_KEY'
)

alert_data = {
    'alert_name': 'C2 Communication Detected',
    'severity': 'critical',
    'src_ip': '10.0.0.50',
    'dest_ip': '198.51.100.1',
    'domain': 'malicious-c2.com',
    'mitre_technique': 'T1071'
}

# Create event in MISP
event = misp.create_event_from_alert(alert_data)

# Enrich alert with threat intel
enrichment = misp.enrich_alert(alert_data)
print(f"Threat Intelligence: {enrichment}")
```

### ThreatConnect Integration

```python
#!/usr/bin/env python3
import requests
import json
import hmac
import hashlib
import base64
from datetime import datetime

class ThreatConnectIntegration:
    def __init__(self, api_url, api_id, api_secret):
        self.api_url = api_url
        self.api_id = api_id
        self.api_secret = api_secret

    def _generate_auth_header(self, path, method='GET'):
        """Generate ThreatConnect authentication header"""
        timestamp = str(int(datetime.now().timestamp()))
        signature_data = f"{path}:{method}:{timestamp}"

        signature = base64.b64encode(
            hmac.new(
                self.api_secret.encode(),
                signature_data.encode(),
                hashlib.sha256
            ).digest()
        ).decode()

        return {
            'Timestamp': timestamp,
            'ApiId': self.api_id,
            'Signature': signature,
            'Content-Type': 'application/json'
        }

    def create_incident(self, alert_data):
        """Create incident in ThreatConnect"""

        incident = {
            'name': alert_data.get('alert_name'),
            'status': 'New',
            'eventDate': datetime.now().isoformat(),
            'summary': alert_data.get('description'),
            'attribute': [
                {
                    'type': 'Source IP',
                    'value': alert_data.get('src_ip')
                },
                {
                    'type': 'Destination IP',
                    'value': alert_data.get('dest_ip')
                }
            ],
            'tag': [
                {'name': 'Splunk'},
                {'name': alert_data.get('severity')}
            ]
        }

        path = '/api/v3/incidents'
        headers = self._generate_auth_header(path, 'POST')

        response = requests.post(
            f"{self.api_url}{path}",
            headers=headers,
            data=json.dumps({'incident': incident})
        )

        return response.json()

    def search_indicators(self, indicator_value):
        """Search for indicators in ThreatConnect"""

        path = f"/api/v3/indicators?filters=summary={indicator_value}"
        headers = self._generate_auth_header(path)

        response = requests.get(
            f"{self.api_url}{path}",
            headers=headers
        )

        return response.json()

    def get_threat_assessment(self, ip_address):
        """Get threat assessment for an IP"""

        indicators = self.search_indicators(ip_address)

        assessment = {
            'ip_address': ip_address,
            'threat_score': 0,
            'confidence': 0,
            'tags': [],
            'associated_groups': []
        }

        if indicators.get('data'):
            for indicator in indicators['data']:
                assessment['threat_score'] = max(
                    assessment['threat_score'],
                    indicator.get('threatAssessScore', 0)
                )
                assessment['confidence'] = max(
                    assessment['confidence'],
                    indicator.get('confidence', 0)
                )
                assessment['tags'].extend(
                    [tag['name'] for tag in indicator.get('tags', [])]
                )

        return assessment

# Usage
tc = ThreatConnectIntegration(
    'https://api.threatconnect.com',
    'API_ID',
    'API_SECRET'
)

alert_data = {
    'alert_name': 'Suspicious External Communication',
    'severity': 'high',
    'src_ip': '10.0.0.100',
    'dest_ip': '203.0.113.1',
    'description': 'Unusual communication pattern detected'
}

# Create incident
incident = tc.create_incident(alert_data)

# Get threat assessment
assessment = tc.get_threat_assessment(alert_data['dest_ip'])
print(f"Threat Assessment: {assessment}")
```

---

## EDR/XDR Integration

### CrowdStrike Falcon Integration

```python
#!/usr/bin/env python3
from falconpy import Hosts, Detects, Incidents
import json

class CrowdStrikeFalconIntegration:
    def __init__(self, client_id, client_secret):
        self.hosts = Hosts(client_id=client_id, client_secret=client_secret)
        self.detects = Detects(client_id=client_id, client_secret=client_secret)
        self.incidents = Incidents(client_id=client_id, client_secret=client_secret)

    def get_host_info(self, hostname):
        """Get host information from CrowdStrike"""

        # Search for host
        response = self.hosts.query_devices_by_filter(
            filter=f"hostname:'{hostname}'"
        )

        if response['body']['resources']:
            aid = response['body']['resources'][0]

            # Get detailed host info
            host_detail = self.hosts.get_device_details(ids=aid)
            return host_detail['body']['resources'][0]

        return None

    def get_detections(self, hostname=None, ip_address=None):
        """Get detections for a host"""

        filter_string = ""
        if hostname:
            filter_string = f"hostname:'{hostname}'"
        elif ip_address:
            filter_string = f"local_ip:'{ip_address}'"

        response = self.detects.query_detects(filter=filter_string)

        detections = []
        if response['body']['resources']:
            # Get detection details
            details = self.detects.get_detect_summaries(
                body={'ids': response['body']['resources']}
            )
            detections = details['body']['resources']

        return detections

    def create_incident_from_alert(self, alert_data):
        """Create CrowdStrike incident from Splunk alert"""

        # Check if host exists in CrowdStrike
        host_info = self.get_host_info(alert_data.get('hostname'))

        if not host_info:
            return {'error': 'Host not found in CrowdStrike'}

        incident_data = {
            'detection_ids': [],
            'incident_type': 'external_alert',
            'title': alert_data.get('alert_name'),
            'description': alert_data.get('description'),
            'tags': ['splunk', alert_data.get('severity')],
            'hosts': [host_info['device_id']]
        }

        # Check for related detections
        detections = self.get_detections(hostname=alert_data.get('hostname'))
        if detections:
            incident_data['detection_ids'] = [d['detection_id'] for d in detections[:5]]

        # Create incident
        response = self.incidents.create_incidents(body=incident_data)
        return response['body']

    def contain_host(self, hostname):
        """Network contain a host"""

        host_info = self.get_host_info(hostname)
        if host_info:
            response = self.hosts.perform_action(
                action_name="contain",
                ids=[host_info['device_id']]
            )
            return response['body']

        return {'error': 'Host not found'}

    def lift_containment(self, hostname):
        """Remove network containment"""

        host_info = self.get_host_info(hostname)
        if host_info:
            response = self.hosts.perform_action(
                action_name="lift_containment",
                ids=[host_info['device_id']]
            )
            return response['body']

        return {'error': 'Host not found'}

# Usage
crowdstrike = CrowdStrikeFalconIntegration(
    'CLIENT_ID',
    'CLIENT_SECRET'
)

alert_data = {
    'alert_name': 'Suspicious Process Execution',
    'hostname': 'WORKSTATION01',
    'severity': 'high',
    'description': 'PowerShell execution with encoded command detected'
}

# Get host info
host_info = crowdstrike.get_host_info(alert_data['hostname'])

# Get detections
detections = crowdstrike.get_detections(hostname=alert_data['hostname'])

# Create incident
incident = crowdstrike.create_incident_from_alert(alert_data)

print(f"Host Info: {host_info}")
print(f"Detections: {len(detections)} found")
print(f"Incident: {incident}")
```

---

## Cloud Security Integration

### AWS Security Hub Integration

```python
#!/usr/bin/env python3
import boto3
import json
from datetime import datetime

class AWSSecurityHubIntegration:
    def __init__(self, region='us-east-1'):
        self.client = boto3.client('securityhub', region_name=region)
        self.region = region
        self.account_id = boto3.client('sts').get_caller_identity()['Account']

    def create_finding(self, alert_data):
        """Create Security Hub finding from Splunk alert"""

        finding = {
            'SchemaVersion': '2018-10-08',
            'Id': alert_data.get('alert_id'),
            'ProductArn': f'arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default',
            'GeneratorId': 'splunk-security-alerts',
            'AwsAccountId': self.account_id,
            'Types': [self.map_finding_type(alert_data)],
            'CreatedAt': datetime.now().isoformat(),
            'UpdatedAt': datetime.now().isoformat(),
            'Severity': {
                'Label': alert_data.get('severity', 'MEDIUM').upper(),
                'Normalized': self.get_normalized_severity(alert_data.get('severity'))
            },
            'Title': alert_data.get('alert_name'),
            'Description': alert_data.get('description'),
            'Resources': self.map_resources(alert_data),
            'SourceUrl': alert_data.get('splunk_url', ''),
            'RecordState': 'ACTIVE',
            'WorkflowState': 'NEW',
            'Network': {
                'SourceIpV4': alert_data.get('src_ip'),
                'DestinationIpV4': alert_data.get('dest_ip'),
                'SourcePort': alert_data.get('src_port'),
                'DestinationPort': alert_data.get('dest_port')
            }
        }

        response = self.client.batch_import_findings(Findings=[finding])
        return response

    def map_finding_type(self, alert_data):
        """Map alert to AWS finding type"""
        mapping = {
            'Unauthorized SSH Access': 'TTPs/Initial Access',
            'Data Exfiltration': 'Effects/Data Exposure',
            'Privilege Escalation': 'TTPs/Privilege Escalation',
            'Lateral Movement': 'TTPs/Lateral Movement'
        }
        return mapping.get(alert_data.get('alert_name'), 'Unusual Behaviors')

    def get_normalized_severity(self, severity):
        """Get normalized severity (0-100)"""
        mapping = {
            'critical': 90,
            'high': 70,
            'medium': 40,
            'low': 20,
            'informational': 0
        }
        return mapping.get(severity.lower(), 40)

    def map_resources(self, alert_data):
        """Map affected resources"""
        resources = []

        # EC2 Instance
        if alert_data.get('instance_id'):
            resources.append({
                'Type': 'AwsEc2Instance',
                'Id': f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{alert_data.get('instance_id')}",
                'Details': {
                    'AwsEc2Instance': {
                        'IpV4Addresses': [alert_data.get('src_ip')]
                    }
                }
            })

        # S3 Bucket
        if alert_data.get('bucket_name'):
            resources.append({
                'Type': 'AwsS3Bucket',
                'Id': f"arn:aws:s3:::{alert_data.get('bucket_name')}",
                'Details': {
                    'AwsS3Bucket': {
                        'Name': alert_data.get('bucket_name')
                    }
                }
            })

        # Default resource if none specified
        if not resources:
            resources.append({
                'Type': 'Other',
                'Id': f"arn:aws:splunk:{self.region}:{self.account_id}:alert/{alert_data.get('alert_id')}",
                'Details': {
                    'Other': {
                        'Source': 'Splunk',
                        'AlertName': alert_data.get('alert_name')
                    }
                }
            })

        return resources

    def update_finding(self, finding_id, workflow_state):
        """Update finding workflow state"""

        response = self.client.update_findings(
            Filters={'Id': [{'Value': finding_id, 'Comparison': 'EQUALS'}]},
            WorkflowState=workflow_state  # NEW, NOTIFIED, SUPPRESSED, RESOLVED
        )
        return response

# Usage
security_hub = AWSSecurityHubIntegration(region='us-east-1')

alert_data = {
    'alert_id': 'SPLUNK-2024-001',
    'alert_name': 'Unauthorized S3 Access',
    'severity': 'high',
    'description': 'Unusual S3 bucket access pattern detected',
    'src_ip': '10.0.0.100',
    'bucket_name': 'sensitive-data-bucket'
}

finding = security_hub.create_finding(alert_data)
print(f"Created Security Hub finding: {finding}")
```

---

## Network Security Tools

### Firewall Integration (Palo Alto)

```python
#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET
import json

class PaloAltoIntegration:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.base_url = f"https://{firewall_ip}/api"

    def create_security_rule(self, alert_data):
        """Create security rule based on alert"""

        rule_name = f"SPLUNK_{alert_data.get('alert_id')}"

        params = {
            'type': 'config',
            'action': 'set',
            'key': self.api_key,
            'xpath': f"/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='{rule_name}']",
            'element': self.build_rule_xml(alert_data)
        }

        response = requests.post(self.base_url, params=params, verify=False)
        return self.parse_response(response.text)

    def build_rule_xml(self, alert_data):
        """Build security rule XML"""

        rule_xml = f"""
        <entry name="SPLUNK_{alert_data.get('alert_id')}">
            <from><member>any</member></from>
            <to><member>any</member></to>
            <source><member>{alert_data.get('src_ip', 'any')}</member></source>
            <destination><member>{alert_data.get('dest_ip', 'any')}</member></destination>
            <service><member>any</member></service>
            <application><member>any</member></application>
            <action>deny</action>
            <log-start>yes</log-start>
            <log-end>yes</log-end>
            <description>Auto-created from Splunk alert: {alert_data.get('alert_name')}</description>
            <tag><member>splunk-auto-block</member></tag>
        </entry>
        """

        return rule_xml

    def add_to_block_list(self, ip_address, list_name='Splunk_Block_List'):
        """Add IP to dynamic block list"""

        params = {
            'type': 'op',
            'cmd': f'<set><address><entry name="{ip_address}"><ip-netmask>{ip_address}/32</ip-netmask></entry></address></set>',
            'key': self.api_key
        }

        response = requests.post(self.base_url, params=params, verify=False)
        return self.parse_response(response.text)

    def commit_changes(self):
        """Commit configuration changes"""

        params = {
            'type': 'commit',
            'cmd': '<commit></commit>',
            'key': self.api_key
        }

        response = requests.post(self.base_url, params=params, verify=False)
        return self.parse_response(response.text)

    def parse_response(self, xml_response):
        """Parse XML response"""

        root = ET.fromstring(xml_response)
        status = root.get('status')
        result = root.find('.//result')

        return {
            'status': status,
            'result': result.text if result is not None else None
        }

# Usage
palo_alto = PaloAltoIntegration(
    '192.168.1.1',
    'API_KEY'
)

alert_data = {
    'alert_id': '12345',
    'alert_name': 'Malicious IP Communication',
    'src_ip': '10.0.0.100',
    'dest_ip': '198.51.100.1'
}

# Create blocking rule
rule = palo_alto.create_security_rule(alert_data)

# Add to block list
palo_alto.add_to_block_list(alert_data['dest_ip'])

# Commit changes
palo_alto.commit_changes()

print(f"Firewall rule created: {rule}")
```

---

## Communication Platforms

### Slack Integration

```python
#!/usr/bin/env python3
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import json

class SlackIntegration:
    def __init__(self, bot_token, channel='#security-alerts'):
        self.client = WebClient(token=bot_token)
        self.channel = channel

    def send_alert(self, alert_data):
        """Send formatted alert to Slack"""

        try:
            response = self.client.chat_postMessage(
                channel=self.channel,
                text=f"Security Alert: {alert_data.get('alert_name')}",
                blocks=self.format_alert_blocks(alert_data),
                attachments=self.format_attachments(alert_data)
            )
            return response
        except SlackApiError as e:
            print(f"Error sending message: {e.response['error']}")
            return None

    def format_alert_blocks(self, alert_data):
        """Format alert as Slack blocks"""

        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'informational': '⚪'
        }.get(alert_data.get('severity', '').lower(), '⚫')

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} {alert_data.get('alert_name')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{alert_data.get('severity', 'Unknown').upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{alert_data.get('_time', 'N/A')}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{alert_data.get('description', 'No description available')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Source IP:*\n`{alert_data.get('src_ip', 'N/A')}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Destination IP:*\n`{alert_data.get('dest_ip', 'N/A')}`"
                    }
                ]
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View in Splunk"
                        },
                        "url": alert_data.get('splunk_url', '#')
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Acknowledge"
                        },
                        "action_id": "acknowledge_alert",
                        "value": alert_data.get('alert_id')
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Create Incident"
                        },
                        "action_id": "create_incident",
                        "value": alert_data.get('alert_id'),
                        "style": "primary"
                    }
                ]
            }
        ]

        return blocks

    def format_attachments(self, alert_data):
        """Format additional details as attachments"""

        color_map = {
            'critical': '#FF0000',
            'high': '#FF8C00',
            'medium': '#FFD700',
            'low': '#0000FF',
            'informational': '#808080'
        }

        attachments = [
            {
                "color": color_map.get(alert_data.get('severity', '').lower(), '#808080'),
                "fields": [
                    {
                        "title": "User",
                        "value": alert_data.get('user', 'N/A'),
                        "short": True
                    },
                    {
                        "title": "Host",
                        "value": alert_data.get('host', 'N/A'),
                        "short": True
                    },
                    {
                        "title": "Alert ID",
                        "value": alert_data.get('alert_id', 'N/A'),
                        "short": True
                    },
                    {
                        "title": "MITRE Technique",
                        "value": alert_data.get('mitre_technique', 'N/A'),
                        "short": True
                    }
                ],
                "footer": "Splunk Security Monitoring",
                "footer_icon": "https://example.com/splunk-icon.png",
                "ts": alert_data.get('timestamp', 0)
            }
        ]

        return attachments

    def send_thread_update(self, thread_ts, update_text):
        """Send update to existing thread"""

        try:
            response = self.client.chat_postMessage(
                channel=self.channel,
                thread_ts=thread_ts,
                text=update_text
            )
            return response
        except SlackApiError as e:
            print(f"Error sending thread update: {e.response['error']}")
            return None

# Usage
slack = SlackIntegration(
    bot_token='xoxb-your-token',
    channel='#security-alerts'
)

alert_data = {
    'alert_name': 'Critical Security Alert',
    'severity': 'critical',
    'description': 'Unauthorized access detected from external IP',
    'src_ip': '203.0.113.1',
    'dest_ip': '10.0.0.100',
    'user': 'admin',
    'host': 'production-server',
    'alert_id': 'ALERT-12345',
    'splunk_url': 'https://splunk.example.com/alert/12345'
}

response = slack.send_alert(alert_data)
print(f"Alert sent to Slack: {response}")
```

---

## API Reference

### Splunk REST API Endpoints

```python
#!/usr/bin/env python3
import requests
import json
from urllib.parse import quote

class SplunkAPIClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.auth = (username, password)
        self.headers = {'Content-Type': 'application/json'}

    def search(self, query, earliest='-15m', latest='now'):
        """Execute search query"""

        search_query = {
            'search': f"search {query}",
            'earliest_time': earliest,
            'latest_time': latest,
            'output_mode': 'json'
        }

        response = requests.post(
            f"{self.base_url}/services/search/jobs",
            auth=self.auth,
            data=search_query
        )

        if response.status_code == 201:
            sid = response.headers.get('Location').split('/')[-1]
            return self.get_search_results(sid)

        return None

    def get_search_results(self, sid):
        """Get search job results"""

        # Wait for search to complete
        while True:
            status = requests.get(
                f"{self.base_url}/services/search/jobs/{sid}",
                auth=self.auth,
                params={'output_mode': 'json'}
            )

            job_status = status.json()['entry'][0]['content']

            if job_status['isDone']:
                break

        # Get results
        results = requests.get(
            f"{self.base_url}/services/search/jobs/{sid}/results",
            auth=self.auth,
            params={'output_mode': 'json'}
        )

        return results.json()

    def create_saved_search(self, name, search, schedule='*/5 * * * *'):
        """Create a saved search"""

        saved_search = {
            'name': name,
            'search': search,
            'is_scheduled': '1',
            'cron_schedule': schedule,
            'dispatch.earliest_time': '-5m',
            'dispatch.latest_time': 'now',
            'alert.track': '1',
            'alert.severity': '3'
        }

        response = requests.post(
            f"{self.base_url}/servicesNS/admin/search/saved/searches",
            auth=self.auth,
            data=saved_search
        )

        return response.status_code == 201

    def trigger_alert_action(self, alert_name, action_name, action_config):
        """Trigger custom alert action"""

        endpoint = f"{self.base_url}/servicesNS/-/-/alerts/fired_alerts/{alert_name}/actions"

        action_data = {
            'action.name': action_name,
            **action_config
        }

        response = requests.post(
            endpoint,
            auth=self.auth,
            data=action_data
        )

        return response.json()

# Usage
splunk_api = SplunkAPIClient(
    'https://splunk.example.com:8089',
    'admin',
    'password'
)

# Execute search
results = splunk_api.search(
    'index=security sourcetype=failed_auth | stats count by src_ip'
)

# Create saved search
splunk_api.create_saved_search(
    'High_Risk_Authentication',
    'index=security EventCode=4625 | stats count by src_ip | where count > 10'
)
```

---

## Webhook Configuration

### Generic Webhook Handler

```python
#!/usr/bin/env python3
from flask import Flask, request, jsonify
import json
import hashlib
import hmac

app = Flask(__name__)

class WebhookHandler:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.handlers = {}

    def register_handler(self, alert_type, handler_func):
        """Register handler for specific alert type"""
        self.handlers[alert_type] = handler_func

    def verify_signature(self, payload, signature):
        """Verify webhook signature"""
        expected_sig = hmac.new(
            self.secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_sig, signature)

    def process_alert(self, alert_data):
        """Process incoming alert"""

        alert_type = alert_data.get('alert_name')
        handler = self.handlers.get(alert_type, self.default_handler)

        return handler(alert_data)

    def default_handler(self, alert_data):
        """Default alert handler"""
        print(f"Received alert: {alert_data}")
        return {'status': 'processed', 'handler': 'default'}

# Initialize webhook handler
webhook_handler = WebhookHandler(secret_key='your-secret-key')

# Register specific handlers
def handle_ssh_alert(alert_data):
    # Custom logic for SSH alerts
    return {'status': 'processed', 'handler': 'ssh_alert'}

def handle_exfiltration_alert(alert_data):
    # Custom logic for data exfiltration
    return {'status': 'processed', 'handler': 'exfiltration'}

webhook_handler.register_handler('Unauthorized SSH Access', handle_ssh_alert)
webhook_handler.register_handler('Data Exfiltration', handle_exfiltration_alert)

@app.route('/webhook/splunk', methods=['POST'])
def splunk_webhook():
    """Endpoint for Splunk webhooks"""

    # Verify signature
    signature = request.headers.get('X-Splunk-Signature')
    if not webhook_handler.verify_signature(request.data.decode(), signature):
        return jsonify({'error': 'Invalid signature'}), 401

    # Process alert
    alert_data = request.json
    result = webhook_handler.process_alert(alert_data)

    return jsonify(result), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

---

## Data Format Standards

### Common Event Format (CEF)

```python
#!/usr/bin/env python3
import re
from datetime import datetime

class CEFFormatter:
    def __init__(self):
        self.version = 0
        self.device_vendor = 'Splunk'
        self.device_product = 'Security Alerts'
        self.device_version = '1.0'

    def format_alert(self, alert_data):
        """Format alert as CEF"""

        # CEF header
        header = self.build_header(alert_data)

        # CEF extension
        extension = self.build_extension(alert_data)

        return f"{header}|{extension}"

    def build_header(self, alert_data):
        """Build CEF header"""

        severity = self.map_severity(alert_data.get('severity'))

        header = f"CEF:{self.version}|{self.device_vendor}|{self.device_product}|{self.device_version}|{alert_data.get('alert_id')}|{alert_data.get('alert_name')}|{severity}"

        return header

    def build_extension(self, alert_data):
        """Build CEF extension"""

        extensions = {
            'src': alert_data.get('src_ip'),
            'dst': alert_data.get('dest_ip'),
            'spt': alert_data.get('src_port'),
            'dpt': alert_data.get('dest_port'),
            'suser': alert_data.get('user'),
            'msg': alert_data.get('description'),
            'act': alert_data.get('action', 'alert'),
            'rt': str(int(datetime.now().timestamp() * 1000)),
            'cs1Label': 'AlertID',
            'cs1': alert_data.get('alert_id'),
            'cs2Label': 'MITRETechnique',
            'cs2': alert_data.get('mitre_technique')
        }

        # Build extension string
        extension_str = ' '.join([
            f"{k}={self.escape_cef_value(v)}"
            for k, v in extensions.items() if v
        ])

        return extension_str

    def escape_cef_value(self, value):
        """Escape special characters in CEF values"""
        if value is None:
            return ''

        value = str(value)
        value = value.replace('\\', '\\\\')
        value = value.replace('|', '\\|')
        value = value.replace('=', '\\=')

        return value

    def map_severity(self, severity):
        """Map severity to CEF scale (0-10)"""
        mapping = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'informational': 1
        }
        return mapping.get(severity.lower(), 5)

# Usage
cef_formatter = CEFFormatter()

alert_data = {
    'alert_id': 'ALERT-12345',
    'alert_name': 'Unauthorized SSH Access',
    'severity': 'critical',
    'src_ip': '203.0.113.1',
    'dest_ip': '10.0.0.100',
    'dest_port': 22,
    'user': 'root',
    'description': 'SSH access from unauthorized IP address',
    'mitre_technique': 'T1021.004'
}

cef_message = cef_formatter.format_alert(alert_data)
print(f"CEF: {cef_message}")
```

### STIX Format

```python
#!/usr/bin/env python3
from stix2 import Indicator, Malware, Relationship, Bundle
import json

class STIXFormatter:
    def __init__(self):
        self.objects = []

    def create_indicator(self, alert_data):
        """Create STIX indicator from alert"""

        pattern_value = f"[ipv4-addr:value = '{alert_data.get('src_ip')}']"

        indicator = Indicator(
            pattern=pattern_value,
            pattern_type="stix",
            name=alert_data.get('alert_name'),
            description=alert_data.get('description'),
            labels=["malicious-activity"],
            valid_from=datetime.now()
        )

        self.objects.append(indicator)
        return indicator

    def create_bundle(self):
        """Create STIX bundle"""
        return Bundle(objects=self.objects)

    def to_json(self):
        """Export as JSON"""
        bundle = self.create_bundle()
        return bundle.serialize(pretty=True)

# Usage
stix_formatter = STIXFormatter()
indicator = stix_formatter.create_indicator(alert_data)
stix_json = stix_formatter.to_json()
print(f"STIX: {stix_json}")
```

---

## Integration Testing

### Test Harness

```python
#!/usr/bin/env python3
import unittest
import json
from unittest.mock import Mock, patch

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.test_alert = {
            'alert_name': 'Test Alert',
            'severity': 'high',
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.50',
            'description': 'Test alert description'
        }

    def test_slack_integration(self):
        """Test Slack integration"""
        with patch('slack_sdk.WebClient') as mock_client:
            mock_client.return_value.chat_postMessage.return_value = {'ok': True}

            slack = SlackIntegration('test-token')
            result = slack.send_alert(self.test_alert)

            self.assertIsNotNone(result)
            mock_client.return_value.chat_postMessage.assert_called_once()

    def test_servicenow_integration(self):
        """Test ServiceNow integration"""
        with patch('requests.post') as mock_post:
            mock_post.return_value.json.return_value = {'sys_id': '12345'}

            snow = ServiceNowIntegration('https://test.service-now.com', 'user', 'pass')
            incident = snow.create_incident(self.test_alert)

            self.assertEqual(incident['sys_id'], '12345')
            mock_post.assert_called_once()

    def test_webhook_signature(self):
        """Test webhook signature verification"""
        handler = WebhookHandler('test-secret')

        payload = json.dumps(self.test_alert)
        signature = hmac.new(
            'test-secret'.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        self.assertTrue(handler.verify_signature(payload, signature))
        self.assertFalse(handler.verify_signature(payload, 'invalid-signature'))

if __name__ == '__main__':
    unittest.main()
```

---

## Document Metadata

**Version:** 1.0
**Last Updated:** 2024-10-18
**Next Review:** 2024-11-18
**Owner:** Security Operations Team
**Classification:** Internal Use Only