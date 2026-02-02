from jinja2 import Template


HTML_TEMPLATE = """
<h1>NetAssetX Scan Report</h1>
{% for host in hosts %}
<h2>{{ host.ip }}</h2>
<p>OS: {{ host.os.name }} ({{ host.os.confidence }})</p>
<p>Risk: {{ host.risk.level }} ({{ host.risk.score }})</p>
<ul>
{% for port in host.open_ports %}
<li>Port {{ port }}</li>
{% endfor %}
</ul>
{% endfor %}
"""


def export_html(scan_result: dict, filename: str):
    template = Template(HTML_TEMPLATE)
    html = template.render(hosts=scan_result["hosts"])

    with open(filename, "w") as f:
        f.write(html)
