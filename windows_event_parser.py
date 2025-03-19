import argparse
import csv
import datetime
import json
import os
import re
import sys
from collections import Counter, defaultdict

# Define event IDs and their meanings
EVENT_DEFINITIONS = {
    # Security log events
    "4624": "Successful logon",
    "4625": "Failed logon attempt",
    "4634": "Account logoff",
    "4648": "Explicit logon (using RunAs or network logon)",
    "4672": "Special privileges assigned to new logon (admin login)",
    "4720": "User account created",
    "4725": "User account disabled",
    "4726": "User account deleted",
    "4738": "User account changed",
    "4740": "User account locked out",
    
    # System log events
    "1074": "System shutdown initiated",
    "6005": "Event log service started",
    "6006": "Event log service stopped",
    "6008": "Unexpected shutdown",
    "6013": "System uptime",
    "7036": "Service started or stopped",
    
    # Application log events
    "1000": "Application error",
    "1001": "Windows Error Reporting",
    "1002": "Application hang",
    
    # System errors
    "41": "System rebooted without clean shutdown",
    "1001": "BSOD/System Error",
    "7001": "Service failed to start",
    "7022": "Service hung",
    "7023": "Service terminated with error",
    "7024": "Service terminated with service-specific error",
    "7026": "Boot-start service failed",
    "7031": "Service terminated unexpectedly",
    "7034": "Service terminated unexpectedly",
    "7043": "Service failed to start in a timely fashion",
}

# Define BSOD/bugcheck codes and their meanings
BUGCHECK_CODES = {
    "0x0000000A": "IRQL_NOT_LESS_OR_EQUAL - A kernel-mode process or driver attempted to access a memory location without authorization",
    "0x0000001E": "KMODE_EXCEPTION_NOT_HANDLED - An exception was not handled in kernel mode",
    "0x00000024": "NTFS_FILE_SYSTEM - NTFS file system error",
    "0x0000002E": "DATA_BUS_ERROR - Memory or data bus error",
    "0x0000003B": "SYSTEM_SERVICE_EXCEPTION - An exception happened while executing a system service routine",
    "0x0000003D": "INTERRUPT_EXCEPTION_NOT_HANDLED - Interrupt exception not handled",
    "0x0000004E": "PFN_LIST_CORRUPT - Page frame number list corruption",
    "0x0000007B": "INACCESSIBLE_BOOT_DEVICE - Windows cannot access the boot device",
    "0x0000007E": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED - A system thread generated an exception that could not be handled",
    "0x0000007F": "UNEXPECTED_KERNEL_MODE_TRAP - Unexpected kernel mode trap",
    "0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA - Invalid system memory was referenced",
    "0x000000C2": "BAD_POOL_CALLER - Memory pool corruption",
    "0x000000C4": "DRIVER_VERIFIER_DETECTED_VIOLATION - Driver Verifier detected a violation",
    "0x000000C5": "DRIVER_CORRUPTED_EXPOOL - A driver corrupted a memory pool",
    "0x000000D1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL - A driver tried to access memory at an improper IRQL",
    "0x000000D8": "DRIVER_USED_EXCESSIVE_PTES - A driver has used too many page table entries (PTEs)",
    "0x000000F4": "CRITICAL_OBJECT_TERMINATION - Critical system process terminated",
    "0x00000109": "CRITICAL_STRUCTURE_CORRUPTION - Critical system structure corruption",
    "0x0000009F": "DRIVER_POWER_STATE_FAILURE - Driver power state failure",
    "0x000000BE": "ATTEMPTED_WRITE_TO_READONLY_MEMORY - A driver attempted to write to read-only memory",
    "0x000000C9": "DRIVER_VERIFIER_IOMANAGER_VIOLATION - Driver Verifier IO Manager detected a violation",
    "0x000000CE": "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS - Driver unloaded without canceling pending operations",
    "0x000000DE": "POOL_CORRUPTION_IN_FILE_AREA - Pool corruption in file area",
    "0x000000E2": "MANUALLY_INITIATED_CRASH - Crash initiated by user",
    "0x000000E3": "RESOURCE_NOT_OWNED - Resource not owned",
    "0x000000EF": "CRITICAL_PROCESS_DIED - Critical process died",
    "0x000000F7": "DRIVER_OVERRAN_STACK_BUFFER - Driver overran a stack-based buffer",
    "0x000000FC": "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY - Attempted execution of non-executable memory",
    "0x000000FD": "DIRTY_NOWRITE_PAGES_CONGESTION - Dirty pages that cannot be written are congested",
    "0x000000FE": "HARDWARE_INTERRUPT_STORM - Hardware interrupt storm",
}

# Define logon types and their meanings
LOGON_TYPES = {
    "2": "Interactive (local logon)",
    "3": "Network (connection to shared folder)",
    "4": "Batch (scheduled task)",
    "5": "Service (Service startup)",
    "7": "Unlock (workstation unlock)",
    "8": "NetworkCleartext (credentials sent in cleartext)",
    "9": "NewCredentials (RunAs or mapped drive)",
    "10": "RemoteInteractive (Terminal Services, Remote Desktop)",
    "11": "CachedInteractive (logon using cached credentials)",
    "12": "CachedRemoteInteractive (cached Terminal Server)",
    "13": "CachedUnlock (cached unlock)"
}

# Define failed logon reason codes
FAILURE_REASONS = {
    "0xC0000064": "The username does not exist",
    "0xC000006A": "Incorrect password",
    "0xC000006D": "Bad username or authentication information",
    "0xC000006E": "Unknown username or bad password",
    "0xC000006F": "Account logon time restriction violation",
    "0xC0000070": "Account logon restriction violation",
    "0xC0000071": "Account expired",
    "0xC0000072": "Account disabled",
    "0xC0000193": "Account expired",
    "0xC0000224": "Password expired",
    "0xC0000234": "Account locked out",
    "0xC0000413": "Authentication firewall failure",
    "0xC000015B": "The user has not been granted the requested logon type at this machine"
}

def parse_evt_file(file_path):
    """
    Parse an .evt or .evtx file and return event data.
    In a real implementation, this would use the Win32 API or a library like python-evtx.
    For now, we'll simulate with a simplified version.
    """
    print(f"Note: This script requires the Windows Event Logs to be exported to CSV or XML format.")
    print(f"Cannot directly parse .evt/.evtx files in this implementation.")
    return []

def parse_csv_file(file_path):
    """Parse a CSV export of Windows Event Logs"""
    events = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                events.append(row)
    except Exception as e:
        print(f"Error parsing CSV file: {e}")
    return events

def parse_xml_file(file_path):
    """
    Parse an XML export of Windows Event Logs.
    In a real implementation, this would use an XML parser.
    """
    print(f"XML parsing is not implemented in this version. Please export logs as CSV.")
    return []

def detect_unusual_logins(events):
    """Detect unusual login patterns"""
    # Track login data
    user_login_times = defaultdict(list)
    user_login_sources = defaultdict(Counter)
    user_failed_attempts = defaultdict(int)
    user_logon_types = defaultdict(Counter)
    admin_logins = []
    
    unusual_events = []
    
    for event in events:
        # Extract fields based on expected CSV format
        # Adjust these field names based on your actual export format
        event_id = event.get('EventID', '')
        username = event.get('TargetUserName', event.get('User', ''))
        timestamp_str = event.get('TimeCreated', event.get('Date and Time', ''))
        source_ip = event.get('IpAddress', event.get('Source Network Address', ''))
        logon_type = event.get('LogonType', '')
        status = event.get('Status', event.get('Keywords', ''))
        
        # Normalize timestamp
        try:
            if not timestamp_str:
                continue
            # Try different timestamp formats
            try:
                timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    timestamp = datetime.datetime.strptime(timestamp_str, '%m/%d/%Y %I:%M:%S %p')
                except ValueError:
                    timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError:
            print(f"Warning: Could not parse timestamp '{timestamp_str}'")
            continue
        
        # Skip events without a username
        if not username or username == 'N/A' or username == '-':
            continue
            
        # Process successful logins (EventID 4624)
        if event_id == '4624':
            # Record login time
            user_login_times[username].append(timestamp)
            
            # Record source IP
            if source_ip and source_ip != '-' and source_ip != 'localhost':
                user_login_sources[username][source_ip] += 1
                
            # Record logon type
            if logon_type:
                user_logon_types[username][logon_type] += 1
                
            # Record admin logins (Special privileges - EventID 4672)
            if event_id == '4672':
                admin_logins.append({
                    'username': username,
                    'timestamp': timestamp,
                    'source': source_ip
                })
                
        # Track failed login attempts (EventID 4625)
        elif event_id == '4625':
            user_failed_attempts[username] += 1
            
            # Get failure reason
            failure_code = event.get('Status', event.get('SubStatus', ''))
            failure_reason = FAILURE_REASONS.get(failure_code, 'Unknown reason')
            
            # Check for multiple failed attempts
            if user_failed_attempts[username] >= 3:
                unusual_events.append({
                    'type': 'Multiple Failed Logins',
                    'username': username,
                    'count': user_failed_attempts[username],
                    'last_attempt': timestamp,
                    'failure_reason': failure_reason,
                    'severity': 'High'
                })
    
    # Analyze login patterns
    for username, login_times in user_login_times.items():
        if len(login_times) < 2:
            continue
            
        # Sort login times
        login_times.sort()
        
        # Check for logins at unusual hours (11PM - 5AM)
        night_logins = [t for t in login_times if t.hour >= 23 or t.hour <= 5]
        if night_logins:
            unusual_events.append({
                'type': 'Off-hours Login',
                'username': username,
                'count': len(night_logins),
                'times': [t.strftime('%Y-%m-%d %H:%M:%S') for t in night_logins[:5]],  # Show first 5
                'severity': 'Medium'
            })
            
        # Check for rapid logins from different sources
        if len(user_login_sources[username]) > 1:
            # Get top 3 sources
            top_sources = user_login_sources[username].most_common(3)
            unusual_events.append({
                'type': 'Multiple Login Sources',
                'username': username,
                'sources': top_sources,
                'severity': 'Medium'
            })
            
        # Check for unusual logon types
        if user_logon_types[username]:
            unusual_types = []
            for logon_type, count in user_logon_types[username].items():
                # Consider types 3, 8, 9, 10 as potentially suspicious in some contexts
                if logon_type in ['3', '8', '9', '10']:
                    unusual_types.append({
                        'type': logon_type,
                        'description': LOGON_TYPES.get(logon_type, 'Unknown'),
                        'count': count
                    })
            
            if unusual_types:
                unusual_events.append({
                    'type': 'Unusual Logon Types',
                    'username': username,
                    'logon_types': unusual_types,
                    'severity': 'Low'
                })
    
    return unusual_events

def analyze_system_errors(events):
    """Analyze system errors including BSODs"""
    system_errors = []
    
    # Track BSOD events
    bsod_events = []
    unexpected_shutdowns = []
    service_failures = []
    
    for event in events:
        # Extract fields based on expected CSV format
        event_id = event.get('EventID', '')
        source = event.get('Source', event.get('ProviderName', ''))
        timestamp_str = event.get('TimeCreated', event.get('Date and Time', ''))
        description = event.get('Description', event.get('Message', ''))
        
        # Normalize timestamp
        try:
            if not timestamp_str:
                continue
            # Try different timestamp formats
            try:
                timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    timestamp = datetime.datetime.strptime(timestamp_str, '%m/%d/%Y %I:%M:%S %p')
                except ValueError:
                    timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError:
            continue
        
        # Check for BSOD events
        if (event_id == '1001' and source == 'BugCheck') or (event_id == '1001' and 'BlueScreen' in str(description)):
            # Extract bugcheck code if present in description
            bugcheck_code = None
            if description:
                # Look for hex values like 0x0000000A
                match = re.search(r'0x[0-9A-F]{8,10}', str(description), re.IGNORECASE)
                if match:
                    bugcheck_code = match.group(0).upper()
            
            bsod_event = {
                'type': 'Blue Screen of Death',
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'bugcheck_code': bugcheck_code,
                'explanation': BUGCHECK_CODES.get(bugcheck_code, 'Unknown or custom error code'),
                'details': description[:200] + '...' if description and len(description) > 200 else description,
                'severity': 'High'
            }
            bsod_events.append(bsod_event)
            
        # Check for unexpected shutdowns
        elif event_id == '6008':
            unexpected_shutdowns.append({
                'type': 'Unexpected Shutdown',
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'details': description[:200] + '...' if description and len(description) > 200 else description,
                'severity': 'Medium'
            })
            
        # Check for critical service failures
        elif event_id in ['7001', '7022', '7023', '7024', '7026', '7031', '7034', '7043']:
            # Extract service name if present in description
            service_name = 'Unknown Service'
            if description:
                # Simple regex to find service name, adjust as needed
                match = re.search(r'service\s+\'(.*?)\'', str(description), re.IGNORECASE)
                if match:
                    service_name = match.group(1)
                else:
                    match = re.search(r'The\s+(.*?)\s+service', str(description), re.IGNORECASE)
                    if match:
                        service_name = match.group(1)
            
            service_failures.append({
                'type': 'Service Failure',
                'event_id': event_id,
                'description': EVENT_DEFINITIONS.get(event_id, 'Unknown event'),
                'service': service_name,
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'details': description[:200] + '...' if description and len(description) > 200 else description,
                'severity': 'Medium'
            })
    
    # Combine all system errors
    system_errors.extend(bsod_events)
    system_errors.extend(unexpected_shutdowns)
    system_errors.extend(service_failures)
    
    # Sort by timestamp
    system_errors.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return system_errors

def generate_report(unusual_logins, system_errors, output_format='text', output_file=None):
    """Generate a report of the analysis results"""
    if output_format == 'json':
        # Generate JSON report
        report = {
            'unusual_logins': unusual_logins,
            'system_errors': system_errors,
            'generated_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_unusual_logins': len(unusual_logins),
            'total_system_errors': len(system_errors)
        }
        
        # Write to file or stdout
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"JSON report written to {output_file}")
        else:
            print(json.dumps(report, indent=2))
            
    else:  # Default to text format
        # Generate text report
        report = []
        report.append("=" * 80)
        report.append("WINDOWS EVENT LOG ANALYSIS REPORT")
        report.append(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)
        
        # Report unusual logins
        report.append("\nUNUSUAL LOGIN EVENTS")
        report.append("-" * 40)
        
        if not unusual_logins:
            report.append("No unusual login events detected.")
        else:
            for i, event in enumerate(unusual_logins, 1):
                report.append(f"\n{i}. {event['type']} [Severity: {event['severity']}]")
                report.append(f"   User: {event['username']}")
                
                if event['type'] == 'Multiple Failed Logins':
                    report.append(f"   Failed attempts: {event['count']}")
                    report.append(f"   Last attempt: {event['last_attempt']}")
                    report.append(f"   Failure reason: {event['failure_reason']}")
                    
                elif event['type'] == 'Off-hours Login':
                    report.append(f"   Count: {event['count']}")
                    report.append(f"   Times: {', '.join(event['times'])}")
                    
                elif event['type'] == 'Multiple Login Sources':
                    source_list = [f"{source} ({count} times)" for source, count in event['sources']]
                    report.append(f"   Sources: {', '.join(source_list)}")
                    
                elif event['type'] == 'Unusual Logon Types':
                    for logon in event['logon_types']:
                        report.append(f"   Type {logon['type']} ({logon['description']}): {logon['count']} times")
        
        # Report system errors
        report.append("\n\nSYSTEM ERRORS AND CRITICAL EVENTS")
        report.append("-" * 40)
        
        if not system_errors:
            report.append("No system errors detected.")
        else:
            for i, error in enumerate(system_errors, 1):
                report.append(f"\n{i}. {error['type']} [Severity: {error['severity']}]")
                report.append(f"   Time: {error['timestamp']}")
                
                if error['type'] == 'Blue Screen of Death':
                    if error['bugcheck_code']:
                        report.append(f"   Bugcheck code: {error['bugcheck_code']}")
                        report.append(f"   Explanation: {error['explanation']}")
                    report.append(f"   Details: {error['details']}")
                    
                elif error['type'] == 'Service Failure':
                    report.append(f"   Service: {error['service']}")
                    report.append(f"   Event ID: {error['event_id']} - {error['description']}")
                    report.append(f"   Details: {error['details']}")
                    
                else:  # Unexpected shutdowns and other errors
                    report.append(f"   Details: {error['details']}")
        
        # Write to file or stdout
        report_text = "\n".join(report)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"Text report written to {output_file}")
        else:
            print(report_text)

def main():
    parser = argparse.ArgumentParser(description='Windows Event Log Parser and Analyzer')
    parser.add_argument('file', help='Path to the event log file (CSV format)')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--output', help='Output file path (default: stdout)')
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' not found.")
        return 1
    
    # Determine file type and parse accordingly
    file_ext = os.path.splitext(args.file)[1].lower()
    events = []
    
    if file_ext == '.csv':
        events = parse_csv_file(args.file)
    elif file_ext in ['.evt', '.evtx']:
        events = parse_evt_file(args.file)
    elif file_ext == '.xml':
        events = parse_xml_file(args.file)
    else:
        print(f"Unsupported file type: {file_ext}")
        print("Please provide a CSV export from Windows Event Viewer.")
        return 1
    
    if not events:
        print("No events found in the file or file could not be parsed.")
        return 1
    
    # Analyze events
    unusual_logins = detect_unusual_logins(events)
    system_errors = analyze_system_errors(events)
    
    # Generate report
    generate_report(unusual_logins, system_errors, args.format, args.output)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
