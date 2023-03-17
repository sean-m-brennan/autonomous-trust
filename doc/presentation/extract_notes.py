#!/usr/bin/env -S python3

from bs4 import BeautifulSoup

with open('index.html', 'r') as in_:
    html = in_.read()

soup = BeautifulSoup(html, 'html.parser')
note_divs = soup.find_all("div", {"class": "notes"})
notes = []
for div in note_divs:
    span = div.find('span')
    if span:
        notes.append(div.find('span').get_text())

with open('notes', 'w') as out_:
    for idx, note in enumerate(notes, start=1):
        note = note.replace('            ', '').strip()
        out_.write('%d.\n%s\n---\n\n' % (idx, note))
