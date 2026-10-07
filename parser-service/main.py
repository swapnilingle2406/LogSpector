"""LogSpector parser. Usage: python main.py <file>  -> prints JSON to stdout."""
import sys, re, json, csv, io

IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
APACHE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)')
SYSLOG = re.compile(r'^(?:<\d+>)?([A-Z][a-z]{2}\s+\d+\s[\d:]{8})\s(\S+)\s([^:]+):\s(.*)')
APPLOG = re.compile(r'^(\d{4}-\d{2}-\d{2}[ T][\d:.,]+Z?)\s+\[?(DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\]?\s+(.*)', re.I)

def first_ip(text):
    m = IP.search(text or '')
    return m.group(0) if m else None

def entry(ip=None, timestamp=None, status=None, request=None, raw=''):
    return {'ip': ip, 'timestamp': timestamp, 'status': str(status) if status else None,
            'request': request, 'raw': raw[:300]}

def detect(text):
    lines = [l for l in text.splitlines() if l.strip()]
    head = lines[0].strip() if lines else ''
    if '"Records"' in text and 'eventName' in text: return 'AWS CloudTrail'
    if head.startswith('{') or head.startswith('['): return 'JSON'
    if 'EventID' in text or 'Event ID' in text or 'Microsoft-Windows' in text: return 'Windows Events'
    if any(APACHE.match(l) for l in lines[:5]):
        return 'Nginx' if 'nginx' in text.lower() else 'Apache'
    if re.search(r'\b(SRC|DST)=', text) or re.search(r'\b(ALLOW|DENY|DROP|BLOCK)\b.*\b(TCP|UDP|ICMP)\b', text, re.I):
        return 'Firewall'
    if any(SYSLOG.match(l) for l in lines[:5]): return 'Syslog'
    if any(APPLOG.match(l) for l in lines[:5]): return 'Custom App'
    if head.count(',') >= 2 and not IP.match(head): return 'CSV'
    return 'Plain Text'

def parse(text, fmt):
    out = []
    lines = [l for l in text.splitlines() if l.strip()]
    if fmt == 'AWS CloudTrail':
        for r in json.loads(text).get('Records', []):
            out.append(entry(r.get('sourceIPAddress'), r.get('eventTime'), r.get('errorCode') or 'OK',
                             f"{r.get('eventSource')}:{r.get('eventName')}", json.dumps(r)))
    elif fmt == 'JSON':
        try:
            data = json.loads(text); data = data if isinstance(data, list) else [data]
        except ValueError:
            data = []
            for l in lines:
                try: data.append(json.loads(l))
                except ValueError: pass
        for d in data:
            g = lambda *k: next((d[x] for x in k if x in d), None)
            out.append(entry(g('ip', 'src_ip', 'client_ip', 'remote_addr') or first_ip(json.dumps(d)),
                             g('timestamp', 'time', '@timestamp'), g('status', 'status_code'),
                             g('request', 'message', 'msg', 'path'), json.dumps(d)))
    elif fmt == 'CSV':
        for row in csv.DictReader(io.StringIO(text)):
            low = {k.lower().strip(): v for k, v in row.items() if k}
            out.append(entry(low.get('ip') or low.get('src_ip') or first_ip(','.join(map(str, row.values()))),
                             low.get('timestamp') or low.get('time') or low.get('date'),
                             low.get('status') or low.get('status_code'),
                             low.get('request') or low.get('message') or low.get('action'), str(row)))
    else:
        for l in lines:
            if fmt in ('Apache', 'Nginx'):
                m = APACHE.match(l)
                if m: out.append(entry(m[1], m[2], m[4], m[3], l)); continue
            elif fmt == 'Syslog':
                m = SYSLOG.match(l)
                if m: out.append(entry(first_ip(m[4]), m[1], None, f'{m[3]}: {m[4]}', l)); continue
            elif fmt == 'Custom App':
                m = APPLOG.match(l)
                if m: out.append(entry(first_ip(m[3]), m[1], m[2].upper(), m[3], l)); continue
            elif fmt == 'Firewall':
                act = re.search(r'\b(ALLOW|DENY|DROP|BLOCK|ACCEPT)\b', l, re.I)
                src = re.search(r'SRC=(\S+)', l)
                out.append(entry(src.group(1) if src else first_ip(l), l[:19],
                                 act.group(1).upper() if act else None, l, l)); continue
            out.append(entry(first_ip(l), None, None, l, l))
    return out

if __name__ == '__main__':
    try:
        text = open(sys.argv[1], encoding='utf-8', errors='ignore').read()
        fmt = detect(text)
        try: entries = parse(text, fmt)
        except Exception: fmt, entries = 'Plain Text', parse(text, 'Plain Text')
        print(json.dumps({'format': fmt, 'entries': entries}))
    except Exception as e:
        print(json.dumps({'format': 'Error', 'entries': [], 'error': str(e)})); sys.exit(1)
