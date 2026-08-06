--[[
******************
 Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
******************

Pandoc filter: impose fixed relative column widths on every table.

Pandoc derives a pipe table's column widths from the dash counts in its
separator row, and it bakes them into each generated longtable, so the preamble
cannot override them. That is a problem here because the markdown gets
normalized by a table formatter on save: every cell is padded to its column's
widest content, so a column of one-line labels beside a column of prose ends up
at roughly 8% / 92% and the labels wrap to three or four lines.

Setting the widths here instead means the source ratios no longer matter and
the formatter is free to reflow the markdown.

Requires pandoc 2.10 or newer (the current Table AST). On older pandoc the
Table filter simply never fires and the source ratios apply as before.
--]]

local ratios = {
  [2] = { 0.30, 0.70 },
  [3] = { 0.10, 0.32, 0.58 },
}

function Table (tbl)
  local ratio = ratios[#tbl.colspecs]
  if not ratio then
    return nil
  end
  local specs = tbl.colspecs
  for i = 1, #specs do
    specs[i] = { specs[i][1], ratio[i] }
  end
  tbl.colspecs = specs
  return tbl
end
