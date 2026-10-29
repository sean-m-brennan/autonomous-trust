"""Generate the DV002 OV-1 (air/space fog-and-edge fleet) as SVG.

Style follows doc/tekfive/NV059/proposal/autonomoustrust_ov1_nv059.svg, but
every state and needline is told apart by line style as well as color, so the
figure reads in black and white (DAF D2P2 instructions).

    python3 gen_ov1_dv002.py autonomoustrust_ov1_dv002.svg
    rsvg-convert -z 2 autonomoustrust_ov1_dv002.svg -o autonomoustrust_ov1_dv002.png
"""
import math
import sys

MONO = "ui-monospace, 'SF Mono', 'Roboto Mono', 'DejaVu Sans Mono', Menlo, Consolas, monospace"
SANS = "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, 'DejaVu Sans', sans-serif"

W, H = 1200, 920

STYLE = f"""
  .bg{{fill:#e4eaf0}}
  .frame{{fill:#ffffff;stroke:#c3ced8;stroke-width:1}}
  .frameline{{stroke:#c3ced8;stroke-width:1}}
  .figbar{{font-family:{MONO};font-size:12.5px;letter-spacing:.08em;fill:#5d7081;font-weight:600}}
  .figbar.b{{fill:#16222e}}
  .z-space{{fill:#e3eef3}}
  .z-air{{fill:#eff5f8}}
  .z-ground{{fill:#f4f5f2}}
  .zone-line{{stroke:#9fb0bd;stroke-width:1;stroke-dasharray:2 6}}
  .zone-label{{font-family:{MONO};font-size:12px;letter-spacing:.16em;fill:#5d7081}}
  .cohort{{fill:none;stroke:#0a6f7a;stroke-width:1.4;stroke-dasharray:2 6}}
  .cohort-label{{font-family:{MONO};font-size:11px;letter-spacing:.12em;fill:#0a5a63}}
  .edge{{fill:none;stroke-linecap:round}}
  .edge.track{{stroke:#0a6f7a;stroke-width:2.4}}
  .edge.fog{{stroke:#16222e;stroke-width:2.6;stroke-dasharray:14 5 3 5;stroke-linecap:butt}}
  .edge.inject{{stroke:#b8322e;stroke-width:2.2;stroke-dasharray:7 6}}
  .edge.reach{{stroke:#6c7f8e;stroke-width:1.8;stroke-dasharray:2 6}}
  .cut{{stroke:#b8322e;stroke-width:3;stroke-linecap:round}}
  .ah-track{{fill:#0a6f7a}} .ah-red{{fill:#b8322e}}
  .node-ring{{fill:#ffffff;stroke-width:2.4}}
  .node-ring.good{{stroke:#1f7a4a}}
  .node-ring.forming{{stroke:#9a6a10;stroke-dasharray:7 4}}
  .node-ring.bad{{stroke:#b8322e;stroke-width:3.6}}
  .node-ring.bad-inner{{fill:none;stroke:#b8322e;stroke-width:1.2}}
  .node-ring.infra{{stroke:#6c7f8e;stroke-dasharray:2 4;stroke-width:2}}
  .glyph{{fill:none;stroke:#16222e;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}}
  .glyph.filled{{fill:#16222e;stroke:none}}
  .glyph.infra{{stroke:#47596a}}
  .node-label{{font-family:{MONO};font-size:12.5px;fill:#16222e;font-weight:700}}
  .node-sub{{font-family:{SANS};font-size:11.5px;fill:#3d4f5f}}
  .score{{font-family:{MONO};font-size:12px;font-weight:700}}
  .score.good{{fill:#1f7a4a}} .score.forming{{fill:#9a6a10}} .score.bad{{fill:#b8322e}}
  .badge-bg{{fill:#16222e}}
  .badge-t{{font-family:{MONO};font-size:10px;letter-spacing:.06em;fill:#ffffff;font-weight:700}}
  .chip{{fill:#ffffff;stroke:#16222e;stroke-width:1.2}}
  .chip-t{{font-family:{MONO};font-size:9px;letter-spacing:.05em;fill:#16222e;font-weight:700}}
  .hotl{{font-family:{MONO};font-size:9.5px;letter-spacing:.04em;fill:#0a5a63;font-weight:700}}
  .edge-label{{font-family:{SANS};font-size:11px;fill:#3d4f5f;font-style:italic}}
  .edge-label.red{{fill:#b8322e;font-style:normal;font-weight:600}}
  .callout{{fill:#ffffff;stroke:#16222e;stroke-width:1.1}}
  .callout-h{{font-family:{MONO};font-size:10.5px;letter-spacing:.12em;fill:#16222e;font-weight:700}}
  .callout-n{{font-family:{MONO};font-size:11px;fill:#16222e;font-weight:700}}
  .callout-t{{font-family:{SANS};font-size:11.5px;fill:#3d4f5f}}
  .legend-h{{font-family:{MONO};font-size:11px;letter-spacing:.16em;fill:#5d7081;font-weight:700}}
  .leg-text{{font-family:{SANS};font-size:12.5px;fill:#3d4f5f}}
  .leg-b{{fill:#16222e;font-weight:700}}
  .footer{{font-family:{MONO};font-size:10.5px;letter-spacing:.02em;fill:#5d7081}}
"""

# --- glyphs (drawn about 0,0, fit inside r=27) --------------------------------

def g_quad():
    s = '<circle cx="0" cy="0" r="4.5" class="glyph"/>'
    for sx in (-1, 1):
        for sy in (-1, 1):
            s += (f'<line x1="{4.5*sx}" y1="{3.1*sy}" x2="{13*sx}" y2="{9*sy}" class="glyph"/>'
                  f'<circle cx="{13*sx}" cy="{9*sy}" r="4" class="glyph"/>')
    return s

def g_wing():
    return ('<path d="M 0 -15 L 0 13" class="glyph"/>'
            '<path d="M -17 1 L 0 -4 L 17 1" class="glyph"/>'
            '<path d="M -7 13 L 0 10 L 7 13" class="glyph"/>')

def g_sat():
    s = ('<rect x="-5.5" y="-7" width="11" height="14" rx="1.5" class="glyph"/>'
         '<rect x="-20" y="-5" width="11" height="10" class="glyph"/>'
         '<rect x="9" y="-5" width="11" height="10" class="glyph"/>'
         '<line x1="-9" y1="0" x2="-5.5" y2="0" class="glyph"/>'
         '<line x1="5.5" y1="0" x2="9" y2="0" class="glyph"/>'
         '<line x1="-14.5" y1="-5" x2="-14.5" y2="5" class="glyph"/>'
         '<line x1="14.5" y1="-5" x2="14.5" y2="5" class="glyph"/>'
         '<line x1="0" y1="7" x2="0" y2="12" class="glyph"/>'
         '<circle cx="0" cy="13.5" r="1.6" class="glyph filled"/>')
    return s

def g_server():
    return ('<rect x="-12" y="-13" width="24" height="7.5" rx="1.5" class="glyph"/>'
            '<rect x="-12" y="-3.5" width="24" height="7.5" rx="1.5" class="glyph"/>'
            '<rect x="-12" y="6" width="24" height="7.5" rx="1.5" class="glyph"/>'
            '<circle cx="7" cy="-9.2" r="1.3" class="glyph filled"/>'
            '<circle cx="7" cy="0.3" r="1.3" class="glyph filled"/>'
            '<circle cx="7" cy="9.8" r="1.3" class="glyph filled"/>')

def g_sensor():
    return ('<line x1="0" y1="-11" x2="0" y2="12" class="glyph"/>'
            '<line x1="-8" y1="12" x2="8" y2="12" class="glyph"/>'
            '<path d="M 4 -10 A 12 12 0 0 1 4 10" class="glyph"/>'
            '<path d="M 9 -13 A 17 17 0 0 1 9 13" class="glyph"/>'
            '<circle cx="0" cy="-11" r="2" class="glyph filled"/>')

def g_console():
    return ('<rect x="-13" y="-8" width="26" height="16" rx="2" class="glyph"/>'
            '<line x1="0" y1="8" x2="0" y2="13" class="glyph"/>'
            '<line x1="-7" y1="13" x2="7" y2="13" class="glyph"/>'
            '<circle cx="14" cy="-9" r="3" class="glyph"/>'
            '<path d="M 9 -1 A 5 5 0 0 1 19 -1" class="glyph"/>')

def g_pki():
    c = 'glyph infra'
    return (f'<path d="M -16 -3 L 0 -15 L 16 -3" class="{c}"/>'
            f'<rect x="-13" y="-3" width="26" height="16" class="{c}"/>'
            f'<line x1="-6" y1="13" x2="-6" y2="2" class="{c}"/>'
            f'<line x1="0" y1="13" x2="0" y2="2" class="{c}"/>'
            f'<line x1="6" y1="13" x2="6" y2="2" class="{c}"/>')

def g_dish(cls='glyph'):
    return (f'<path d="M -14 -6 A 15 15 0 0 0 6 14" class="{cls}"/>'
            f'<line x1="-14" y1="-6" x2="6" y2="14" class="{cls}"/>'
            f'<line x1="-4" y1="4" x2="8" y2="-8" class="{cls}"/>'
            f'<circle cx="9.5" cy="-9.5" r="2" class="{cls} filled"/>'
            f'<line x1="-6" y1="10" x2="-10" y2="16" class="{cls}"/>'
            f'<line x1="-14" y1="16" x2="-2" y2="16" class="{cls}"/>')

# --- primitives ---------------------------------------------------------------

out = []

def add(s):
    out.append(s)

def chip(x, y, text):
    w = 8 + 6.2 * len(text)
    return (f'<g transform="translate({x} {y})"><rect class="chip" x="0" y="0" width="{w:.0f}" '
            f'height="15" rx="3"/><text class="chip-t" x="{w/2:.1f}" y="11" '
            f'text-anchor="middle">{text}</text></g>')

def badge(x, y, text):
    w = 10 + 6.6 * len(text)
    return (f'<g transform="translate({x - w/2:.1f} {y})"><rect class="badge-bg" x="0" y="0" '
            f'width="{w:.0f}" height="17" rx="3"/><text class="badge-t" x="{w/2:.1f}" y="12.3" '
            f'text-anchor="middle">{text}</text></g>')

NODES = {}

def node(key, x, y, state, glyph, label, sub, score=None, score_side='right',
         chips=(), anchor='middle', extra='', label_dx=None):
    NODES[key] = (x, y)
    s = f'<g transform="translate({x} {y})">'
    s += f'<circle class="node-ring {state}" cx="0" cy="0" r="27"/>'
    if state == 'bad':
        s += '<circle class="node-ring bad-inner" cx="0" cy="0" r="22"/>'
    s += glyph
    lx = {'middle': 0, 'start': -25, 'end': 25}[anchor] if label_dx is None else label_dx
    s += f'<text class="node-label" x="{lx}" y="45" text-anchor="{anchor}">{label}</text>'
    if sub:
        s += f'<text class="node-sub" x="{lx}" y="60" text-anchor="{anchor}">{sub}</text>'
    if score is not None:
        sc = {'good': 'good', 'forming': 'forming', 'bad': 'bad'}.get(state, 'good')
        if score_side == 'left-low':
            s += f'<text class="score {sc}" x="-33" y="5" text-anchor="end">R={score}</text>'
        elif score_side == 'right':
            s += f'<text class="score {sc}" x="31" y="-21" text-anchor="start">R={score}</text>'
        else:
            s += f'<text class="score {sc}" x="-31" y="-21" text-anchor="end">R={score}</text>'
    for (cx, cy, t) in chips:
        s += chip(cx, cy, t)
    s += extra
    s += '</g>'
    add(s)

def clip(a, b, ra=31, rb=33):
    (x1, y1), (x2, y2) = NODES[a], NODES[b]
    d = math.hypot(x2 - x1, y2 - y1)
    ux, uy = (x2 - x1) / d, (y2 - y1) / d
    return x1 + ux * ra, y1 + uy * ra, x2 - ux * rb, y2 - uy * rb

def edge(a, b, cls, marker=None, ra=31, rb=33):
    x1, y1, x2, y2 = clip(a, b, ra, rb)
    m = f' marker-end="url(#{marker})"' if marker else ''
    add(f'<path class="edge {cls}" d="M {x1:.1f} {y1:.1f} L {x2:.1f} {y2:.1f}"{m}/>')
    return x1, y1, x2, y2

def cut_at(x1, y1, x2, y2, t):
    px, py = x1 + (x2 - x1) * t, y1 + (y2 - y1) * t
    d = math.hypot(x2 - x1, y2 - y1)
    nx, ny = -(y2 - y1) / d, (x2 - x1) / d
    add(f'<line class="cut" x1="{px - nx*10:.1f}" y1="{py - ny*10:.1f}" '
        f'x2="{px + nx*10:.1f}" y2="{py + ny*10:.1f}"/>')
    return px, py

# --- frame and zones ----------------------------------------------------------

FRAME_H = 832
SPACE = (44, 236)
AIR = (236, 540)
GROUND = (540, 720)

add(f'<rect class="bg" x="0" y="0" width="{W}" height="{H}"/>')
add(f'<rect class="frame" x="0.5" y="0.5" width="{W-1}" height="{FRAME_H}" rx="14"/>')
add('<text class="figbar" x="24" y="28"><tspan class="figbar b">OPERATIONAL CONCEPT</tspan>'
    '<tspan xml:space="preserve">  ·  AIR AND SPACE FOG/EDGE FLEET UNDER CYBER ATTACK, CONTESTED (DDIL)'
    '  ·  DAF27TZ01-DV002</tspan></text>')
add(f'<line class="frameline" x1="0" y1="{SPACE[0]}" x2="{W}" y2="{SPACE[0]}"/>')
add(f'<rect class="z-space" x="1" y="{SPACE[0]}" width="{W-2}" height="{SPACE[1]-SPACE[0]}"/>')
add(f'<rect class="z-air" x="1" y="{AIR[0]}" width="{W-2}" height="{AIR[1]-AIR[0]}"/>')
add(f'<rect class="z-ground" x="1" y="{GROUND[0]}" width="{W-2}" height="{GROUND[1]-GROUND[0]}"/>')
for y in (AIR[0], GROUND[0]):
    add(f'<line class="zone-line" x1="0" y1="{y}" x2="{W}" y2="{y}"/>')
add(f'<line class="frameline" x1="0" y1="{GROUND[1]}" x2="{W}" y2="{GROUND[1]}"/>')
add(f'<text class="zone-label" x="20" y="{SPACE[0]+24}">SPACE · LEO</text>')
add(f'<text class="zone-label" x="20" y="{AIR[0]+24}">AIR · CONTESTED, JAMMED (DDIL)</text>')
add(f'<text class="zone-label" x="20" y="{GROUND[0]+24}">GROUND · TACTICAL EDGE AND REACH-BACK</text>')

# cohort boundaries
add('<rect class="cohort" x="290" y="84" width="660" height="140" rx="18"/>')
add('<text class="cohort-label" x="620" y="78" text-anchor="middle">'
    'SMALLSAT COHORT — light-lag, intermittent ground contact</text>')
add('<rect class="cohort" x="190" y="282" width="690" height="248" rx="20"/>')
add('<text class="cohort-label" x="204" y="276">'
    'sUAS ISR COHORT — responds on its own</text>')
add('<rect class="cohort" x="560" y="578" width="530" height="132" rx="18"/>')
add('<text class="cohort-label" x="660" y="572">'
    'IoBT COHORT — sub-threshold quorum, capped admission</text>')

# --- nodes (positions first, edges drawn under nodes) ---------------------------

LAYOUT = {
    'sat1': (360, 140), 'sat2': (490, 140), 'satgw': (640, 140), 'sat3': (870, 140),
    'uplink': (1090, 140),
    'uas1': (300, 335), 'uas2': (300, 445), 'uas3': (520, 458), 'fusion': (640, 400),
    'uas4': (1010, 330),
    'pki': (90, 630), 'ops': (290, 630), 'gndgw': (640, 635), 'iobt1': (820, 635),
    'iobt2': (1000, 635),
}
NODES.update(LAYOUT)

edges = []
def later(fn):
    edges.append(fn)

# needlines
edge('uas1', 'fusion', 'track', 'arrow-track')
edge('uas2', 'fusion', 'track', 'arrow-track')
edge('uas3', 'fusion', 'track', 'arrow-track')
for k in ('sat1', 'sat2', 'sat3'):
    edge(k, 'satgw', 'track', 'arrow-track')
edge('iobt1', 'gndgw', 'track', 'arrow-track')
x1, y1, x2, y2 = edge('uas4', 'fusion', 'inject', 'arrow-red')
cx, cy = cut_at(x1, y1, x2, y2, 0.40)
add(f'<text class="edge-label red" x="{cx+8:.0f}" y="{cy-14:.0f}" text-anchor="middle">'
    'false track severed</text>')
# IoBT-2 is admitted at a capped tier; its track still flows
edge('iobt2', 'iobt1', 'track', 'arrow-track')
# tampered update at a smallsat, refused
x1, y1, x2, y2 = edge('uplink', 'sat3', 'inject', 'arrow-red')
cx, cy = cut_at(x1, y1, x2, y2, 0.45)
add(f'<text class="edge-label red" x="{cx-6:.0f}" y="{cy+24:.0f}" text-anchor="middle">'
    'unsigned update refused</text>')
# fog tier: reputation roll-up and deep query
fx1, fy1, fx2, fy2 = edge('fusion', 'satgw', 'fog', ra=31, rb=31)
add('<text class="edge-label" x="652" y="258">reputation roll-up / deep query (fog tier)</text>')
edge('fusion', 'gndgw', 'fog', ra=31, rb=31)
# reach-back, contested and off the decision path
edge('ops', 'gndgw', 'reach', ra=31, rb=31)
edge('pki', 'ops', 'reach', ra=31, rb=31)

node('sat1', *LAYOUT['sat1'], 'good', g_sat(), 'SAT-1', 'Smallsat edge node', '0.91')
node('sat2', *LAYOUT['sat2'], 'good', g_sat(), 'SAT-2', 'Smallsat edge node', '0.87')
node('satgw', *LAYOUT['satgw'], 'good', g_sat(), 'SAT-GW', 'Smallsat · fog gateway', '0.94',
     chips=[(-52, -44, 'FOG')], anchor='start', label_dx=14)
node('sat3', *LAYOUT['sat3'], 'good', g_sat(), 'SAT-3', 'Smallsat edge node', '0.89')
node('uplink', *LAYOUT['uplink'], 'bad', g_dish(), 'UPLINK-X', 'Spoofed uplink', None)

node('uas1', *LAYOUT['uas1'], 'good', g_quad(), 'UAS-1', 'ISR sUAS', '0.88')
node('uas2', *LAYOUT['uas2'], 'good', g_wing(), 'UAS-2', 'Legacy payload (gateway)', '0.84',
     chips=[(-62, -8, 'GW')])
node('uas3', *LAYOUT['uas3'], 'forming', g_quad(), 'UAS-3', 'Late joiner, capped tier', '0.62',
     score_side='left-low')
node('fusion', *LAYOUT['fusion'], 'good', g_server(), 'FUSION', 'Track fusion · fog gateway',
     '0.93', chips=[(-30, -46, 'FOG')], anchor='start', label_dx=14)
node('uas4', *LAYOUT['uas4'], 'bad', g_wing(), 'UAS-4', 'Credentialed, compromised', '0.12',
     score_side='left', extra=badge(0, 68, 'TIER-GATED OUT'))

node('pki', *LAYOUT['pki'], 'infra', g_pki(), 'PKI / ICAM', 'Reach-back authority', None,
     anchor='start')
node('ops', *LAYOUT['ops'], 'good', g_console(), 'OPS', 'Mission ops console', '0.95', score_side='left',
     extra='<text class="hotl" x="0" y="76" text-anchor="middle">HUMAN-ON-THE-LOOP</text>')
node('gndgw', *LAYOUT['gndgw'], 'good', g_server(), 'GND-GW', 'Ground fog gateway', '0.92',
     chips=[(-52, -44, 'FOG')])
node('iobt1', *LAYOUT['iobt1'], 'good', g_sensor(), 'IOBT-1', 'Ground sensor', '0.86')
node('iobt2', *LAYOUT['iobt2'], 'forming', g_sensor(), 'IOBT-2', 'Admitted at capped tier', '0.55')

# detection-to-response callout beside the compromised node
cx0, cy0 = 898, 424
add(f'<rect class="callout" x="{cx0}" y="{cy0}" width="290" height="80" rx="6"/>')
add(f'<text class="callout-h" x="{cx0+12}" y="{cy0+17}">AUTONOMOUS RESPONSE · NO REACH-BACK</text>')
steps = [('1', 'Detect', 'track 97.5 m off vs 50 m bound'),
         ('2', 'Demote', 'signed evidence lowers R'),
         ('3', 'Gate out', 'loses data-sharing tier')]
for i, (n, h, t) in enumerate(steps):
    y = cy0 + 36 + i * 16
    add(f'<text class="callout-n" x="{cx0+12}" y="{y}">{n}</text>')
    add(f'<text class="callout-t" x="{cx0+26}" y="{y}"><tspan class="leg-b">{h}</tspan>'
        f' — {t}</text>')

# --- legend ---------------------------------------------------------------------

LY = GROUND[1] + 30
add(f'<text class="legend-h" x="40" y="{LY}">NODE STATE</text>')
items = [('good', 'Trusted', '— above required tier'),
         ('forming', 'Forming', '— capped tier, accruing'),
         ('bad', 'Compromised', '— tier-gated out'),
         ('infra', 'Reach-back', '— off the hot path')]
for i, (st, b, t) in enumerate(items):
    x = 200 + i * 250
    add(f'<circle class="node-ring {st}" cx="{x}" cy="{LY-4}" r="8"/>')
    if st == 'bad':
        add(f'<circle class="node-ring bad-inner" cx="{x}" cy="{LY-4}" r="4.5"/>')
    add(f'<text class="leg-text" x="{x+16}" y="{LY}"><tspan class="leg-b">{b}</tspan> {t}</text>')

LY2 = LY + 34
add(f'<text class="legend-h" x="40" y="{LY2}">NEEDLINES</text>')
lines = [('track', 'arrow-track', 'Track / telemetry flow'),
         ('fog', None, 'Fog-tier reputation roll-up'),
         ('inject', 'arrow-red', 'Hostile input (severed)'),
         ('reach', None, 'Reach-back (contested)')]
for i, (cls, mk, t) in enumerate(lines):
    x = 192 + i * 250
    m = f' marker-end="url(#{mk})"' if mk else ''
    add(f'<path class="edge {cls}" d="M {x} {LY2-4} L {x+44} {LY2-4}"{m}/>')
    if cls == 'inject':
        add(f'<line class="cut" x1="{x+20}" y1="{LY2-12}" x2="{x+20}" y2="{LY2+4}"/>')
    add(f'<text class="leg-text" x="{x+54}" y="{LY2}">{t}</text>')

LY3 = LY2 + 34
add(f'<text class="legend-h" x="40" y="{LY3}">MARKERS</text>')
add(f'<circle class="node-ring good" cx="200" cy="{LY3-4}" r="8"/>')
add(f'<text class="leg-text" x="216" y="{LY3}"><tspan class="leg-b">Resident AT agent</tspan>'
    ' — every ringed node</text>')
add(chip(488, LY3 - 12, 'GW'))
add(f'<text class="leg-text" x="520" y="{LY3}"><tspan class="leg-b">Bump-in-the-wire</tspan>'
    ' gateway</text>')
add(chip(718, LY3 - 12, 'FOG'))
add(f'<text class="leg-text" x="756" y="{LY3}"><tspan class="leg-b">Fog-tier</tspan>'
    ' gateway</text>')
add(f'<rect class="cohort" x="900" y="{LY3-13}" width="30" height="18" rx="5"/>')
add(f'<text class="leg-text" x="940" y="{LY3}"><tspan class="leg-b">Cohort boundary</tspan></text>')

FY = FRAME_H + 30
add(f'<text class="footer" x="40" y="{FY}">SBIR/STTR DATA RIGHTS — use and disclosure restricted per'
    ' the cover-page legend. TekFive, Inc.</text>')
add(f'<text class="footer" x="40" y="{FY+20}">DoDAF OV-1 operational-concept scene · illustrative'
    ' — node set representative of the §4 demonstration; reputation values notional.</text>')

DEFS = ('<defs>'
        '<marker id="arrow-track" viewBox="0 0 10 10" refX="8" refY="5" markerUnits="userSpaceOnUse" '
        'markerWidth="12" markerHeight="12" orient="auto"><path d="M0,0 L10,5 L0,10 z" class="ah-track"/></marker>'
        '<marker id="arrow-red" viewBox="0 0 10 10" refX="8" refY="5" markerUnits="userSpaceOnUse" '
        'markerWidth="12" markerHeight="12" orient="auto"><path d="M0,0 L10,5 L0,10 z" class="ah-red"/></marker>'
        '</defs>')

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
       f'role="img" aria-label="DoDAF OV-1 for DAF27TZ01-DV002: AutonomousTrust cohorts of smallsats, '
       f'sUAS and ground IoBT sensors detect, demote and gate out a credentialed but compromised edge '
       f'node without reach-back, with fog-tier gateways rolling reputation up the hierarchy.">'
       f'<style>{STYLE}</style>{DEFS}' + '\n'.join(out) + '</svg>\n')

with open(sys.argv[1], 'w') as f:
    f.write(svg)
