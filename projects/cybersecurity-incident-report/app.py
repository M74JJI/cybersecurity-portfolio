from flask import Flask, render_template, request
import os
from network_analysis import analyze_network_log

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filename)
            
            # Analyze the uploaded log file
            dns_issues, icmp_issues, udp_protocol, icmp_error_msg = analyze_network_log(filename)

            # Create a cybersecurity report with the analysis results
            report = generate_report(dns_issues, icmp_issues, udp_protocol, icmp_error_msg)
            return render_template('index.html', report=report)

    return render_template('index.html')

def generate_report(dns_issues, icmp_issues, udp_protocol, icmp_error_msg):
    """Generate the cybersecurity incident report based on the analysis results."""
    
    # Start constructing the report
    report = {}

    # Part 1: DNS and ICMP Traffic Log Summary
    report['part1'] = {
        'dns_summary': "\n".join(dns_issues) if dns_issues else "No DNS issues found.",
        'icmp_summary': "\n".join(icmp_issues) if icmp_issues else "No ICMP issues found.",
        'udp_protocol': udp_protocol if udp_protocol else "No UDP issues found.",
        'icmp_error_msg': icmp_error_msg if icmp_error_msg else "No ICMP error message found."
    }

    # Part 2: Detailed Analysis
    report['part2'] = {
        'time_incident_occurred': "Time of incident: TBD (based on logs or IT team's report).",
        'it_awareness': "The IT team became aware when DNS/ICMP issues were reported by the monitoring system or staff.",
        'investigation_actions': "IT investigated the issue by capturing and analyzing traffic with tools like tcpdump or Wireshark.",
        'key_findings': "Port 443 or other ports might be blocked, DNS queries might not resolve, or the ICMP reply could indicate a service issue.",
        'likely_cause': "Likely cause: Misconfiguration or attack targeting network services (possible DDoS or firewall misconfig)."
    }

    return report

if __name__ == '__main__':
    app.run(debug=True)
