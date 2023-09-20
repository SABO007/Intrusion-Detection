from flask import Flask,request, url_for, redirect, render_template
import pickle
import numpy as np

app = Flask(__name__)
model=pickle.load(open('model.pkl','rb'))

@app.route('/')
def Home():
    return render_template("detection.html")

@app.route('/predict',methods=['POST','GET'])
def predict():
    des = {'phf.': 'The PHF (Print Header Field) attack is a type of web server attack that exploits vulnerabilities in the HTTP server by making a malicious request.',
    'xterm.': 'XTerm is a terminal emulator for the X Window System. In the context of security, this term may refer to attacks targeting XTerm or X Window System vulnerabilities.',
    'multihop.': 'A multihop attack is when an attacker uses multiple intermediaries or compromised systems to conceal their identity and route malicious traffic.',
    'mscan.': 'MScan is a port scanner tool used for network reconnaissance to identify open ports on target systems.',
    'snmpguess.': 'SNMP (Simple Network Management Protocol) guessing is an attack where an attacker tries to guess the SNMP community strings to gain unauthorized access to network devices.',
    'smurf.': 'A smurf attack is a type of denial-of-service (DoS) attack that floods a victim\'s network with ICMP echo requests, often by spoofing the source address.',
    'named.': 'Named refers to BIND, the most widely used DNS (Domain Name System) server software. Attacks targeting BIND can include DNS-based attacks.',
    'udpstorm.': 'UDP storm attacks involve overwhelming a network or system with a flood of UDP (User Datagram Protocol) traffic.',
    'loadmodule.': 'Loadmodule could refer to an attack involving maliciously loading modules or code into a running system, potentially for privilege escalation.',
    'xlock.': 'XLock is a screen-locking utility for the X Window System. An attack involving xlock might aim to bypass or exploit vulnerabilities in the screen-locking mechanism.',
    'snmpgetattack.': 'Similar to SNMP guessing, this attack involves unauthorized access attempts using SNMP.',
    'buffer_overflow.': 'Buffer overflow attacks occur when a program writes more data to a buffer than it can hold, potentially leading to code execution or system compromise.',
    'spy.': 'Spyware or spy-related attacks involve unauthorized surveillance or data collection on a victim\'s system.',
    'back.': 'A "back" attack might refer to a backdoor or unauthorized access point that allows an attacker to maintain access to a compromised system.',
    'mailbomb.': 'A mailbomb is an attack where a victim\'s email address is flooded with a large volume of emails, overwhelming their mailbox and causing disruption.',
    'land.': 'A land attack is a type of DoS attack where the attacker spoofs the source IP address in a TCP/IP packet to make it look like the packet is coming from the target system itself.',
    'satan.': 'Satan (Security Administrator Tool for Analyzing Networks) is a network scanning and vulnerability assessment tool. References to "satan" may imply scanning or assessment activities.',
    'worm.': 'A worm is a self-replicating malicious program that spreads across networks and systems, often causing damage or data theft.',
    'rootkit.': 'A rootkit is a collection of tools and techniques used to gain unauthorized access to a computer or network while hiding the presence of the attacker.',
    'ps.': 'PS (Port Scan) might refer to a network scanning activity, where an attacker scans a range of ports on a target system to identify open services and potential vulnerabilities.',
    'perl.': 'Perl is a programming language, and references to "perl" might imply the use of Perl scripts in attacks or automation.',
    'teardrop.': 'A teardrop attack is a type of DoS attack that involves sending fragmented packets with overlapping offsets, causing the victim\'s system to crash or become unresponsive.',
    'ipsweep.': 'IPsweep is a network scanning technique where an attacker systematically scans a range of IP addresses to identify live hosts on a network.',
    'neptune.': 'Neptune is a reference to the Neptune denial-of-service attack tool, which generates a high volume of traffic to overwhelm a target network or system.',
    'warezmaster.': 'A "warezmaster" might refer to a user or group involved in the distribution of copyrighted software or media without authorization.',
    'guess_passwd.': 'A "guess_passwd" attack involves attempting to guess a user\'s password through brute force or dictionary attacks.',
    'imap.': 'IMAP (Internet Message Access Protocol) is an email protocol, and "imap" references may involve unauthorized access to email accounts using this protocol.',
    'processtable.': 'A processtable attack aims to overwhelm a target system by creating a large number of processes, consuming system resources.',
    'warezclient.': 'A "warezclient" might refer to a user or software client that downloads copyrighted material without authorization.',
    'xsnoop.': 'XSnoop may refer to a network packet capturing or eavesdropping tool used for unauthorized monitoring of network traffic.',
    'httptunnel.': 'HTTP tunneling involves encapsulating non-HTTP traffic within HTTP packets, often used to bypass network security controls.',
    'sendmail.': 'Sendmail is an email server software, and references to "sendmail" may involve vulnerabilities or attacks related to email services.',
    'pod.': 'A pod (Ping of Death) attack is a type of DoS attack that involves sending an oversized ICMP packet to crash or disrupt a target system.',
    'nmap.': 'Nmap (Network Mapper) is a popular network scanning tool used for network discovery and vulnerability assessment. References to "nmap" may imply scanning activities.',
    'apache2.': 'Apache2 is a widely used web server software. References to "apache2" may involve attacks or vulnerabilities related to Apache web servers.',
    'ftp_write.': 'An "ftp_write" attack involves unauthorized write access to an FTP (File Transfer Protocol) server, potentially allowing an attacker to upload malicious files.',
    'sqlattack.': 'A SQL attack involves exploiting vulnerabilities in a web application\'s database by injecting malicious SQL queries.',
    'normal.': 'In the context of network traffic analysis, "normal" refers to legitimate and non-malicious network traffic.',
    'portsweep.': 'A portsweep attack involves scanning a range of ports on multiple target systems to identify open services and potential vulnerabilities.',
    'saint.': 'Saint (Security Administrator\'s Integrated Network Tool) is a network security assessment tool. References to "saint" may imply scanning or assessment activities.'}

    int_features=[float(x) for x in request.form.values()] 
    final=[np.array(int_features)]
    prediction = model.predict(final)
    print(int_features)
    print(prediction[0])

    if prediction[0] in des:
        attack=des[prediction[0]]

    return render_template("detection.html", prediction_text = prediction, attack_text=attack)

if __name__ == '__main__':
    app.run(debug=True)



