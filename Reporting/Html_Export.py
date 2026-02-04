from jinja2 import Template


HTML_TEMPLATE = """
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetAssetX Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; margin: 24px; }
    h1 { margin-bottom: 8px; }
    .meta { color: #444; margin-bottom: 16px; }
    .host { border: 1px solid #ddd; padding: 16px; border-radius: 8px; margin: 16px 0; }
    .host h2 { margin: 0 0 8px 0; }
    .host .info { display: flex; flex-wrap: wrap; gap: 12px; color: #333; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border-bottom: 1px solid #eee; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f7f7f7; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .small { color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h1>NetAssetX Scan Report</h1>
  <div class="meta">
    <div><strong>Timestamp:</strong> {{ metadata.timestamp }}</div>
    <div><strong>Target:</strong> {{ metadata.target_resolved }}</div>
    <div><strong>Ports:</strong> {{ metadata.ports_scanned }}</div>
  </div>

  {% for host in hosts %}
  <div class="host">
    <h2>
      {{ host.ip }}
      {% if host.reverse_dns %} ({{ host.reverse_dns }}){% endif %}
    </h2>
    <div class="info">
      <div><strong>MAC:</strong> {{ host.mac or "N/A" }}</div>
      <div><strong>OS:</strong> {{ host.os.name }} ({{ host.os.confidence }})</div>
      <div><strong>Risk:</strong> {{ host.risk.level }} ({{ host.risk.score }})</div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Port</th>
          <th>Service</th>
          <th>Banner</th>
          <th>HTTP</th>
          <th>TLS</th>
        </tr>
      </thead>
      <tbody>
        {% for port, svc in host.services|dictsort %}
        <tr>
          <td><code>{{ port }}</code></td>
          <td>{{ svc.service }}</td>
          <td><div class="small">{{ svc.banner or "" }}</div></td>
          <td>
            {% if svc.http %}
              <div class="small">{{ svc.http.status_line }}</div>
              {% if svc.http.headers.get('server') %}
                <div class="small">Server: {{ svc.http.headers.get('server') }}</div>
              {% endif %}
              {% if svc.http.headers.get('content-type') %}
                <div class="small">Type: {{ svc.http.headers.get('content-type') }}</div>
              {% endif %}
            {% endif %}
          </td>
          <td>
            {% if svc.tls %}
              <div class="small">CN: {{ svc.tls.cn }}</div>
              <div class="small">Issuer: {{ svc.tls.issuer_cn }}</div>
              <div class="small">Version: {{ svc.tls.version }}</div>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endfor %}
</body>
</html>
"""


def export_html(scan_result: dict, filename: str):
    template = Template(HTML_TEMPLATE)
    html = template.render(hosts=scan_result["hosts"], metadata=scan_result["metadata"])

    with open(filename, "w") as f:
        f.write(html)
