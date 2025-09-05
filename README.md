# Personal-Firewall
The Personal Firewall Project is a Python-based simulation of a firewall that monitors and controls incoming or outgoing network traffic based on predefined rules. The goal is to understand the fundamentals of firewall rule processing, IP filtering, and access control while building a lightweight prototype.

This project implements a basic firewall system that allows users to define, monitor, and control network traffic rules through a user-friendly graphical interface. The backend logic leverages Scrapy for data parsing and filtering capabilities, while the Tkinter library is used to design an intuitive GUI for easy interaction.

The firewall provides functionality to:

Define rules to allow or block specific IP addresses, ports, or protocols.

Simulate packet inspection by analyzing incoming/outgoing traffic against predefined rules.

Provide real-time feedback on whether a connection is allowed or denied.

Store and display logs of blocked/allowed traffic for monitoring.

The Scrapy framework is utilized to handle structured data parsing and filtering, making it easier to match traffic patterns against firewall rules. On top of this, the Tkinter GUI enables users—even without command-line expertise—to configure rules, visualize traffic flow, and manage the firewall dynamically.
