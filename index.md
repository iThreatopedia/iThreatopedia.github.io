---
layout: page
title: iThreatopedia
---

<script async src="https://www.googletagmanager.com/gtag/js?id="></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', '');
</script>

<div class="header-box">
<a href="https://github.com/iThreatopedia/iThreatopedia.github.io/blob/main/README.md"><img src="{{ '/assets/logo.png' | relative_url }}" height="150" style="margin-right: 10px;"></a>
<div>
<h2 style="margin-top: 0">Threat Hunting for macOS</h2>
Below is a list of Tactics, Techniques and Procedures (TTP's) targeting the macOS operating system. Within each TTP, you will find:
<br>
<br>
<ul>
  <li>information about each TTP</li>
  <li>a way to reproduce the TTP using <a href="https://www.prelude.org">Prelude Operator</a></li>
  <li>detection queries using Endpoint Detection and Response (EDR)</li>
</ul>
<br>
<br>
<span style="font-style: italic;">MITRE ATT&amp;CK&reg; and ATT&amp;CK&reg; are registered trademarks of The MITRE Corporation.</span> You can see the current ATT&amp;CK&reg; mapping of this project on the <a href="https://mitre-attack.github.io/attack-navigator/#layerURL={{ '/mitre_attack_navigator_layer.json' | absolute_url | replace:"http://","https://" }}">ATT&amp;CK&reg; Navigator</a> (be sure to click the "expand annotated sub-techniques under the layer controls on the top right!).

</div>
</div>

[tactics]: /tactics/

{% include technique_table.html %}
