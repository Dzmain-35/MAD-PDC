import os
import json
from collections import Counter

MAD_ROOT = r"\\10.1.64.2\pdc\!Persistent_Folder\MAD Cases"
OUTPUT_HTML = "mad_family_extension_bipartite.html"

EXCLUDE_UNKNOWN = True
ONLY_MALICIOUS = False  # Set True if you want threat_score > 0 only

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
                family = file_entry.get("thq_family")
                threat_score = file_entry.get("threat_score", 0)

                if not family:
                    family = "Unknown"

                if EXCLUDE_UNKNOWN and family == "Unknown":
                    continue

                if ONLY_MALICIOUS and threat_score <= 0:
                    continue

                if filename and "." in filename:
                    ext = "." + filename.split(".")[-1].lower()
                else:
                    ext = "no_extension"

                records.append((family, ext))

print(f"[+] Filtered files used: {len(records)}")

if not records:
    raise RuntimeError("[!] No data after filtering — adjust filters.")

link_counter = Counter(records)

links_data = [
    {"family": f, "extension": e, "count": c}
    for (f, e), c in link_counter.items()
]

families = sorted(set(f for f, e in records))
extensions = sorted(set(e for f, e in records))

height = max(len(families), len(extensions)) * 35 + 200

html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>MAD Family ↔ Extension</title>
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

.family-label {{
    font-size: 15px;
    font-weight: 600;
    fill: #f0f6fc;
    text-shadow: 0 0 6px rgba(255,255,255,0.15);
}}

.extension-label {{
    font-size: 14px;
    font-weight: 500;
    fill: #d0d7de;
    text-shadow: 0 0 4px rgba(255,255,255,0.12);
}}

.link {{
    fill: none;
    stroke: #4da6ff;
    stroke-opacity: 0.6;
    filter: drop-shadow(0px 0px 4px rgba(77,166,255,0.3));
}}

.family-node {{
    fill: #ff4d4d;
    stroke: #ffffff;
    stroke-width: 1.5px;
}}

.extension-node {{
    fill: #66ccff;
    stroke: #ffffff;
    stroke-width: 1px;
}}
</style>
</head>
<body>

<svg width="1600" height="{height}"></svg>

<script>

const families = {json.dumps(families)};
const extensions = {json.dumps(extensions)};
const links = {json.dumps(links_data, indent=2)};

const svg = d3.select("svg");
const width = +svg.attr("width");
const height = +svg.attr("height");

const leftX = 300;
const rightX = width - 300;

const familyScale = d3.scalePoint()
    .domain(families)
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
            "M " + leftX + "," + familyScale(d.family) +
            " C " + (leftX + 200) + "," + familyScale(d.family) +
            " " + (rightX - 200) + "," + extScale(d.extension) +
            " " + rightX + "," + extScale(d.extension)
        );
}});

// Draw family nodes
families.forEach(function(f) {{
    svg.append("circle")
        .attr("class", "family-node")
        .attr("cx", leftX)
        .attr("cy", familyScale(f))
        .attr("r", 10);

    svg.append("text")
        .attr("class", "family-label")
        .attr("x", leftX - 15)
        .attr("y", familyScale(f) + 4)
        .attr("text-anchor", "end")
        .text(f);
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
