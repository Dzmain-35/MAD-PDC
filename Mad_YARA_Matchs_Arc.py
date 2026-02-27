import os
import json
from collections import Counter

MAD_ROOT = r"\\10.1.64.2\pdc\!Persistent_Folder\MAD Cases"
OUTPUT_HTML = "mad_yara_extension_correlation.html"

print(f"[+] Checking path: {MAD_ROOT}")

if not os.path.exists(MAD_ROOT):
    raise RuntimeError(f"[!] Path not accessible: {MAD_ROOT}")

records = []

for root, dirs, files in os.walk(MAD_ROOT):
    for fname in files:
        if fname.lower() == "case_metadata.json":
            with open(os.path.join(root, fname), "r", encoding="utf-8") as f:
                data = json.load(f)

            for file_entry in data.get("files", []):
                filename = file_entry.get("filename")
                yara_matches = file_entry.get("yara_matches", [])

                if not filename:
                    continue

                if "." in filename:
                    ext = "." + filename.split(".")[-1].lower()
                else:
                    ext = "no_extension"

                for match in yara_matches:
                    rule = match.get("rule")
                    if rule:
                        records.append((rule, ext))

print(f"[+] YARA ↔ Extension correlations found: {len(records)}")

if not records:
    raise RuntimeError("[!] No YARA matches found in dataset.")

# Count frequency
link_counter = Counter(records)

links_data = [
    {"rule": r, "extension": e, "count": c}
    for (r, e), c in link_counter.items()
]

rules = sorted(set(r for r, e in records))
extensions = sorted(set(e for r, e in records))

height = max(len(rules), len(extensions)) * 35 + 200

html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>MAD YARA ↔ Extension Correlation</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
body {{
    margin: 0;
    background: #0e1117;
    font-family: "Segoe UI Variable", "Segoe UI", Inter, system-ui, sans-serif;
    color: #e6edf3;
}}

svg {{
    display: block;
    margin: auto;
}}

.rule-label {{
    font-size: 15px;
    font-weight: 600;
    fill: #ffb366;
}}

.extension-label {{
    font-size: 14px;
    font-weight: 500;
    fill: #66ccff;
}}

.link {{
    fill: none;
    stroke: #4da6ff;
    stroke-opacity: 0.6;
}}

.rule-node {{
    fill: #ff8800;
    stroke: white;
    stroke-width: 1.5px;
}}

.extension-node {{
    fill: #66ccff;
    stroke: white;
    stroke-width: 1px;
}}
</style>
</head>
<body>

<svg width="1700" height="{height}"></svg>

<script>

const rules = {json.dumps(rules)};
const extensions = {json.dumps(extensions)};
const links = {json.dumps(links_data, indent=2)};

const svg = d3.select("svg");
const width = +svg.attr("width");
const height = +svg.attr("height");

const leftX = 350;
const rightX = width - 350;

const ruleScale = d3.scalePoint()
    .domain(rules)
    .range([100, height - 100]);

const extScale = d3.scalePoint()
    .domain(extensions)
    .range([100, height - 100]);

// Draw links
links.forEach(function(d) {{
    svg.append("path")
        .attr("class", "link")
        .attr("stroke-width", 1 + d.count)
        .attr("d",
            "M " + leftX + "," + ruleScale(d.rule) +
            " C " + (leftX + 250) + "," + ruleScale(d.rule) +
            " " + (rightX - 250) + "," + extScale(d.extension) +
            " " + rightX + "," + extScale(d.extension)
        );
}});

// Draw rule nodes
rules.forEach(function(r) {{
    svg.append("circle")
        .attr("class", "rule-node")
        .attr("cx", leftX)
        .attr("cy", ruleScale(r))
        .attr("r", 10);

    svg.append("text")
        .attr("class", "rule-label")
        .attr("x", leftX - 15)
        .attr("y", ruleScale(r) + 4)
        .attr("text-anchor", "end")
        .text(r);
}});

// Draw extension nodes
extensions.forEach(function(e) {{
    svg.append("circle")
        .attr("class", "extension-node")
        .attr("cx", rightX)
        .attr("cy", extScale(e))
        .attr("r", 9);

    svg.append("text")
        .attr("class", "extension-label")
        .attr("x", rightX + 15)
        .attr("y", extScale(e) + 4)
        .attr("text-anchor", "start")
        .text(e);
}});

</script>
</body>
</html>
"""

with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
    f.write(html)

print(f"[+] Visualization written to: {OUTPUT_HTML}")
