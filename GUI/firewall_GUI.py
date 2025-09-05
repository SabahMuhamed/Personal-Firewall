import json
import threading
from dataclasses import dataclass, asdict
from ipaddress import ip_address, ip_network
from typing import List, Optional

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Optional dependencies for importing rules from the web
SCRAPY_AVAILABLE = True
try:
    import requests
    from scrapy import Selector
except Exception:
    SCRAPY_AVAILABLE = False


# ----------------------------
# Core data structures
# ----------------------------
@dataclass
class Rule:
    action: str        # "allow" | "block"
    ip: str            # exact IP (e.g., "192.168.1.10") OR CIDR (e.g., "10.0.0.0/24") OR "*" for any
    port: str          # "80", "443", or "*" for any
    protocol: str      # "TCP", "UDP", or "*" for any
    direction: str     # "in", "out", or "*" for any
    note: str = ""     # optional label

    def matches(self, pkt: dict) -> bool:
        """Return True if this rule matches the given packet dict."""
        return (
            match_ip(self.ip, pkt.get("ip"))
            and match_generic(self.port, str(pkt.get("port")))
            and match_generic(self.protocol.upper(), pkt.get("protocol", "").upper())
            and match_generic(self.direction.lower(), pkt.get("direction", "").lower())
        )


def match_generic(rule_val: str, value: str) -> bool:
    if rule_val == "*":
        return True
    return rule_val == value


def match_ip(rule_ip: str, value_ip: str) -> bool:
    if rule_ip == "*" or not value_ip:
        return True
    try:
        # CIDR?
        if "/" in rule_ip:
            return ip_address(value_ip) in ip_network(rule_ip, strict=False)
        # Exact IP
        return ip_address(value_ip) == ip_address(rule_ip)
    except Exception:
        # Fallback to simple equality if parsing fails
        return rule_ip == value_ip


class FirewallEngine:
    """Simple first-match-wins firewall evaluation engine."""

    def __init__(self):
        self.rules: List[Rule] = []
        self.logs: List[dict] = []

    def evaluate(self, pkt: dict) -> str:
        """Return 'allow' or 'block' and add a log entry."""
        for r in self.rules:
            if r.matches(pkt):
                decision = r.action
                self._log(pkt, decision, r)
                return decision
        # Default policy: allow
        decision = "allow"
        self._log(pkt, decision, None)
        return decision

    def _log(self, pkt: dict, decision: str, rule: Optional[Rule]):
        self.logs.append({
            "ip": pkt.get("ip", ""),
            "port": pkt.get("port", ""),
            "protocol": pkt.get("protocol", ""),
            "direction": pkt.get("direction", ""),
            "decision": decision,
            "matched_rule": asdict(rule) if rule else None
        })

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def remove_rule(self, idx: int):
        if 0 <= idx < len(self.rules):
            del self.rules[idx]

    def clear_rules(self):
        self.rules.clear()

    def export_rules_json(self, path: str):
        data = [asdict(r) for r in self.rules]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def import_rules_json(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.rules = [Rule(**item) for item in data]


# ----------------------------
# Optional: Scrapy-powered import
# ----------------------------
def import_rules_from_url(url: str) -> List[Rule]:
    """
    Fetch an HTML page with a table of rules and parse it using Scrapy's Selector.
    Expected table columns (order-insensitive, header text case-insensitive):
      action | ip | port | protocol | direction | note
    Extra columns are ignored. Missing cells default to '*'.
    """
    if not SCRAPY_AVAILABLE:
        raise RuntimeError("Scrapy/requests not available. Install with: pip install scrapy requests")

    resp = requests.get(url, timeout=15)
    resp.raise_for_status()

    sel = Selector(text=resp.text)

    # Heuristic: pick the first table with a header row that contains "action" and "ip".
    tables = sel.css("table")
    selected = None
    for t in tables:
        headers = [h.get().strip().lower() for h in t.css("th::text")]
        if "action" in headers and "ip" in headers:
            selected = t
            break

    if not selected:
        # fallback: any table
        if tables:
            selected = tables[0]
        else:
            raise ValueError("No HTML table found to parse rules from.")

    # Map column indexes by header text (lowercased)
    headers = [h.get().strip().lower() for h in selected.css("th::text")]
    idx = {name: i for i, name in enumerate(headers)}

    def cell(row, name, default="*"):
        if name not in idx:
            return default
        i = idx[name]
        tds = row.css("td")
        if i >= len(tds):
            return default
        return tds[i].xpath("string(.)").get(default="").strip() or default

    rules: List[Rule] = []
    for row in selected.css("tr"):
        if row.css("th"):  # skip header row(s)
            continue
        action = cell(row, "action", "allow").lower()
        if action not in ("allow", "block"):
            # skip weird rows
            continue
        rules.append(
            Rule(
                action=action,
                ip=cell(row, "ip", "*"),
                port=cell(row, "port", "*"),
                protocol=cell(row, "protocol", "*").upper() or "*",
                direction=cell(row, "direction", "*").lower() or "*",
                note=cell(row, "note", "")
            )
        )
    if not rules:
        raise ValueError("No rules parsed from the provided URL.")
    return rules


# ----------------------------
# Tkinter GUI
# ----------------------------
class FirewallGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Firewall Simulator (Tkinter + Scrapy)")
        self.geometry("980x620")
        self.engine = FirewallEngine()

        self._build_layout()

    # ----- UI Layout -----
    def _build_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        main = ttk.Frame(self, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        for i in range(3):
            main.columnconfigure(i, weight=1)
        for r in range(3):
            main.rowconfigure(r, weight=1)

        # Rules frame
        rules_frame = ttk.LabelFrame(main, text="Rules")
        rules_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        rules_frame.columnconfigure(0, weight=1)
        rules_frame.rowconfigure(1, weight=1)

        # Rules table
        self.rules_tree = ttk.Treeview(rules_frame, columns=("action", "ip", "port", "protocol", "direction", "note"),
                                       show="headings", height=10)
        for c, w in (("action", 80), ("ip", 150), ("port", 80), ("protocol", 90), ("direction", 90), ("note", 200)):
            self.rules_tree.heading(c, text=c.capitalize())
            self.rules_tree.column(c, width=w, anchor="center")
        self.rules_tree.grid(row=1, column=0, sticky="nsew")

        rules_btns = ttk.Frame(rules_frame)
        rules_btns.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        for i in range(8):
            rules_btns.columnconfigure(i, weight=1)

        ttk.Button(rules_btns, text="Add Rule", command=self.open_add_rule_dialog).grid(row=0, column=0, sticky="ew")
        ttk.Button(rules_btns, text="Remove Selected", command=self.remove_selected_rule).grid(row=0, column=1, sticky="ew")
        ttk.Button(rules_btns, text="Clear All", command=self.clear_rules).grid(row=0, column=2, sticky="ew")
        ttk.Button(rules_btns, text="Save Rules", command=self.save_rules).grid(row=0, column=3, sticky="ew")
        ttk.Button(rules_btns, text="Load Rules", command=self.load_rules).grid(row=0, column=4, sticky="ew")
        ttk.Button(rules_btns, text="Import from URL", command=self.import_from_url).grid(row=0, column=5, sticky="ew")
        label = "Scrapy: ON" if SCRAPY_AVAILABLE else "Scrapy: OFF"
        ttk.Label(rules_btns, text=label, anchor="center").grid(row=0, column=6, sticky="ew")

        # Packet test frame
        test_frame = ttk.LabelFrame(main, text="Test Packet")
        test_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        for i in range(2):
            test_frame.columnconfigure(i, weight=1)

        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar()
        self.protocol_var = tk.StringVar(value="TCP")
        self.direction_var = tk.StringVar(value="in")

        ttk.Label(test_frame, text="IP:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(test_frame, textvariable=self.ip_var).grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        ttk.Label(test_frame, text="Port:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(test_frame, textvariable=self.port_var).grid(row=1, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(test_frame, text="Protocol:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        proto_combo = ttk.Combobox(test_frame, textvariable=self.protocol_var, values=["TCP", "UDP", "*"], state="readonly")
        proto_combo.grid(row=2, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(test_frame, text="Direction:").grid(row=3, column=0, sticky="e", padx=4, pady=4)
        dir_combo = ttk.Combobox(test_frame, textvariable=self.direction_var, values=["in", "out", "*"], state="readonly")
        dir_combo.grid(row=3, column=1, sticky="ew", padx=4, pady=4)

        ttk.Button(test_frame, text="Evaluate", command=self.evaluate_packet).grid(row=4, column=0, columnspan=2, sticky="ew", padx=4, pady=8)

        self.result_label = ttk.Label(test_frame, text="Decision: —", font=("Segoe UI", 11, "bold"))
        self.result_label.grid(row=5, column=0, columnspan=2, sticky="ew", padx=4, pady=6)

        # Logs frame
        logs_frame = ttk.LabelFrame(main, text="Logs")
        logs_frame.grid(row=1, column=1, rowspan=2, sticky="nsew", padx=5, pady=5)
        logs_frame.columnconfigure(0, weight=1)
        logs_frame.rowconfigure(0, weight=1)

        self.logs_tree = ttk.Treeview(
            logs_frame,
            columns=("ip", "port", "protocol", "direction", "decision", "rule"),
            show="headings",
            height=10
        )
        for c, w in (("ip", 140), ("port", 70), ("protocol", 90), ("direction", 90), ("decision", 90), ("rule", 300)):
            self.logs_tree.heading(c, text=c.capitalize())
            self.logs_tree.column(c, width=w, anchor="center")
        self.logs_tree.grid(row=0, column=0, sticky="nsew")

        ttk.Button(logs_frame, text="Clear Logs", command=self.clear_logs).grid(row=1, column=0, sticky="ew", padx=4, pady=6)

        # Starter hint
        hint = ttk.Label(main, text="Tip: Add a rule like  action=block, ip=192.168.1.10, port=80, protocol=TCP, direction=in",
                         foreground="#666")
        hint.grid(row=2, column=0, sticky="w", padx=5, pady=2)

    # ----- Rule Manipulation -----
    def open_add_rule_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add Rule")
        dialog.geometry("420x300")
        dialog.resizable(False, False)

        vars_ = {
            "action": tk.StringVar(value="block"),
            "ip": tk.StringVar(value="*"),
            "port": tk.StringVar(value="*"),
            "protocol": tk.StringVar(value="*"),
            "direction": tk.StringVar(value="*"),
            "note": tk.StringVar(value="")
        }

        row = 0
        for label, key in [
            ("Action", "action"),
            ("IP (exact/CIDR/*)", "ip"),
            ("Port (* or number)", "port"),
            ("Protocol (TCP/UDP/*)", "protocol"),
            ("Direction (in/out/*)", "direction"),
            ("Note (optional)", "note"),
        ]:
            ttk.Label(dialog, text=label + ":").grid(row=row, column=0, sticky="e", padx=6, pady=6)
            if key in {"action", "protocol", "direction"}:
                values = {
                    "action": ["allow", "block"],
                    "protocol": ["TCP", "UDP", "*"],
                    "direction": ["in", "out", "*"]
                }.get(key, [])
                if values:
                    ttk.Combobox(dialog, textvariable=vars_[key], values=values, state="readonly").grid(row=row, column=1, sticky="ew", padx=6, pady=6)
                else:
                    ttk.Entry(dialog, textvariable=vars_[key]).grid(row=row, column=1, sticky="ew", padx=6, pady=6)
            else:
                ttk.Entry(dialog, textvariable=vars_[key]).grid(row=row, column=1, sticky="ew", padx=6, pady=6)
            row += 1

        dialog.columnconfigure(1, weight=1)

        def add_rule():
            try:
                r = Rule(
                    action=vars_["action"].get(),
                    ip=vars_["ip"].get().strip() or "*",
                    port=vars_["port"].get().strip() or "*",
                    protocol=(vars_["protocol"].get().strip() or "*").upper(),
                    direction=(vars_["direction"].get().strip() or "*").lower(),
                    note=vars_["note"].get().strip()
                )
                self.engine.add_rule(r)
                self.refresh_rules_tree()
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Invalid Rule", str(e))

        btns = ttk.Frame(dialog)
        btns.grid(row=row, column=0, columnspan=2, pady=10, sticky="ew")
        for i in range(2):
            btns.columnconfigure(i, weight=1)

        ttk.Button(btns, text="Add", command=add_rule).grid(row=0, column=0, sticky="ew", padx=6)
        ttk.Button(btns, text="Cancel", command=dialog.destroy).grid(row=0, column=1, sticky="ew", padx=6)

    def refresh_rules_tree(self):
        for i in self.rules_tree.get_children():
            self.rules_tree.delete(i)
        for r in self.engine.rules:
            self.rules_tree.insert("", "end", values=(r.action, r.ip, r.port, r.protocol, r.direction, r.note))

    def remove_selected_rule(self):
        sel = self.rules_tree.selection()
        if not sel:
            return
        idx = self.rules_tree.index(sel[0])
        self.engine.remove_rule(idx)
        self.refresh_rules_tree()

    def clear_rules(self):
        if messagebox.askyesno("Confirm", "Remove all rules?"):
            self.engine.clear_rules()
            self.refresh_rules_tree()

    def save_rules(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            self.engine.export_rules_json(path)
            messagebox.showinfo("Saved", f"Rules saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_rules(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            self.engine.import_rules_json(path)
            self.refresh_rules_tree()
            messagebox.showinfo("Loaded", f"Loaded {len(self.engine.rules)} rules.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def import_from_url(self):
        if not SCRAPY_AVAILABLE:
            messagebox.showwarning("Unavailable", "Scrapy/requests not installed.\n\nInstall with:\npip install scrapy requests")
            return

        # small prompt dialog
        dialog = tk.Toplevel(self)
        dialog.title("Import Rules from URL (Scrapy)")
        dialog.geometry("520x140")
        dialog.resizable(False, False)

        url_var = tk.StringVar(value="https://example.com/firewall-rules.html")
        ttk.Label(dialog, text="URL with an HTML table of rules:").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        ttk.Entry(dialog, textvariable=url_var).grid(row=1, column=0, sticky="ew", padx=8)
        dialog.columnconfigure(0, weight=1)

        status = ttk.Label(dialog, text="")
        status.grid(row=2, column=0, sticky="w", padx=8, pady=(6, 2))

        def run_import():
            url = url_var.get().strip()
            if not url:
                messagebox.showerror("Error", "Please enter a valid URL.")
                return

            def worker():
                try:
                    rules = import_rules_from_url(url)
                    self.engine.rules.extend(rules)
                    self.refresh_rules_tree()
                    status.config(text=f"Imported {len(rules)} rules.")
                except Exception as e:
                    status.config(text=f"Error: {e}")

            threading.Thread(target=worker, daemon=True).start()

        btns = ttk.Frame(dialog)
        btns.grid(row=3, column=0, sticky="ew", padx=8, pady=8)
        for i in range(2):
            btns.columnconfigure(i, weight=1)
        ttk.Button(btns, text="Import", command=run_import).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(btns, text="Close", command=dialog.destroy).grid(row=0, column=1, sticky="ew", padx=4)

    # ----- Packet Evaluation & Logs -----
    def evaluate_packet(self):
        pkt = {
            "ip": self.ip_var.get().strip(),
            "port": self.port_var.get().strip(),
            "protocol": self.protocol_var.get().strip().upper(),
            "direction": self.direction_var.get().strip().lower(),
        }

        # Normalize blanks to "*"
        if not pkt["ip"]:
            pkt["ip"] = "*"
        if not pkt["port"]:
            pkt["port"] = "*"

        decision = self.engine.evaluate(pkt)
        self.result_label.config(text=f"Decision: {decision.upper()}")
        self.refresh_logs_tree_last()

    def refresh_logs_tree_last(self):
        # Append only the latest entry for efficiency
        last = self.engine.logs[-1] if self.engine.logs else None
        if not last:
            return
        rule = last.get("matched_rule")
        rule_short = f'{rule["action"]} {rule["ip"]}:{rule["port"]} {rule["protocol"]} {rule["direction"]}' if rule else "—"
        self.logs_tree.insert("", "end", values=(
            last.get("ip", ""),
            last.get("port", ""),
            last.get("protocol", ""),
            last.get("direction", ""),
            last.get("decision", ""),
            rule_short
        ))

    def clear_logs(self):
        self.engine.logs.clear()
        for i in self.logs_tree.get_children():
            self.logs_tree.delete(i)


if __name__ == "__main__":
    app = FirewallGUI()
    app.mainloop()
