import requests


def cve_to_md(cve_json):
    id = cve_json["id"]
    url = cve_json["url"]
    product = cve_json["product"]
    version = cve_json["version"]
    vulnerability = cve_json["vulnerability"]
    description = cve_json["description"]

    md = f"### [{id}]({url})\n"
    md += "![](https://img.shields.io/static/v1?label=Product&message=n%2Fa&color=blue)\n"
    md += "![](https://img.shields.io/static/v1?label=Version&message=n%2Fa&color=blue)\n"
    md += "![](https://img.shields.io/static/v1?label=Vulnerability&message=n%2Fa&color=brighgreen)\n\n"
    md += f"### Description\n\n{description}\n\n"
    
    if len(cve_json["poc"]) > 0:
        md += "### POC\n\n"
        for poc in cve_json["poc"]:
            md += f"#### {poc['description']}\n\n- {poc['url']}\n\n"

    if len(cve_json["github"]) > 0:
        md += "### Github\n\n"
        for gh in cve_json["github"]:
            md += f"#### {gh['title']}\n\n- {gh['url']}\n\n"

    return md
