#!/usr/bin/env -S python3
# ******************
#  Copyright 2024 TekFive, Inc. and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

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
