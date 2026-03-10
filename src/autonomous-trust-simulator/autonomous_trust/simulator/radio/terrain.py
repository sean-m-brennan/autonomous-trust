# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

import csv
import os
import subprocess
import shlex
from typing import Optional

from ..sim_data import SignalMatrix


class SplatSite:
    """SPLAT! QTH site definition."""
    def __init__(self, site_id: str, name: str, lat: float, lon: float, height_m: float):
        self.site_id = site_id
        self.name = name
        self.lat = lat
        self.lon = lon
        self.height_m = height_m

    def write_qth(self, directory: str) -> str:
        """Write a SPLAT! .qth site file. Returns the file path."""
        filepath = os.path.join(directory, '%s.qth' % self.site_id)
        with open(filepath, 'w') as f:
            f.write('%s\n' % self.name)
            f.write('%.6f\n' % self.lat)
            # SPLAT! expects west longitude as positive
            f.write('%.6f\n' % (-self.lon if self.lon < 0 else self.lon))
            f.write('%.1f\n' % self.height_m)
        return filepath


class TerrainPathLoss:
    """Manages terrain-aware path-loss data from SPLAT! output.

    Loads pre-computed path-loss CSV files and builds a SignalMatrix
    for use by the Simulator. Also provides a batch runner interface
    for generating path-loss data via the SPLAT! CLI.

    CSV format: src_id,dst_id,freq_mhz,path_loss_db
    """

    def __init__(self):
        self._matrices: dict[float, SignalMatrix] = {}  # freq_mhz -> SignalMatrix

    @property
    def frequencies(self) -> list[float]:
        return sorted(self._matrices.keys())

    def get_matrix(self, freq_mhz: float) -> Optional[SignalMatrix]:
        """Get the path-loss SignalMatrix for a given frequency."""
        return self._matrices.get(freq_mhz)

    def get_loss(self, freq_mhz: float, src_id: str, dst_id: str) -> Optional[float]:
        """Get path loss in dB between two sites at a given frequency."""
        matrix = self._matrices.get(freq_mhz)
        if matrix is None:
            return None
        src_row = matrix.get(src_id)
        if src_row is None:
            return None
        return src_row.get(dst_id)

    def load_csv(self, filepath: str) -> None:
        """Load path-loss data from a CSV file.

        Expected columns: src_id, dst_id, freq_mhz, path_loss_db
        """
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                freq = float(row['freq_mhz'])
                src = row['src_id']
                dst = row['dst_id']
                loss = float(row['path_loss_db'])

                if freq not in self._matrices:
                    self._matrices[freq] = {}
                if src not in self._matrices[freq]:
                    self._matrices[freq][src] = {}
                self._matrices[freq][src][dst] = loss

    def save_csv(self, filepath: str, freq_mhz: float = None) -> None:
        """Save path-loss data to a CSV file.

        If freq_mhz is specified, only that frequency is saved.
        Otherwise all frequencies are saved.
        """
        freqs = [freq_mhz] if freq_mhz is not None else self.frequencies
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['src_id', 'dst_id', 'freq_mhz', 'path_loss_db'])
            writer.writeheader()
            for freq in freqs:
                matrix = self._matrices.get(freq, {})
                for src_id, destinations in sorted(matrix.items()):
                    for dst_id, loss in sorted(destinations.items()):
                        writer.writerow({
                            'src_id': src_id,
                            'dst_id': dst_id,
                            'freq_mhz': freq,
                            'path_loss_db': round(loss, 2),
                        })

    @staticmethod
    def run_splat_pair(tx_qth: str, rx_qth: str, freq_mhz: float,
                       sdf_dir: str, output_dir: str) -> Optional[float]:
        """Run SPLAT! for a single TX-RX pair and parse the path loss.

        Requires SPLAT! to be installed and SRTM .sdf tiles in sdf_dir.
        Returns path loss in dB, or None if SPLAT! is not available.
        """
        report_name = os.path.join(output_dir, 'splat_report')
        cmd = 'splat -t %s -r %s -f %.0f -d %s -o %s' % (
            tx_qth, rx_qth, freq_mhz, sdf_dir, report_name)
        try:
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

        # Parse SPLAT! text report for path loss value
        report_file = report_name + '.txt'
        if not os.path.exists(report_file):
            return None
        return TerrainPathLoss._parse_splat_report(report_file)

    @staticmethod
    def _parse_splat_report(report_path: str) -> Optional[float]:
        """Extract path loss from a SPLAT! text report.

        Looks for the line: "Free space path loss: XXX.XX dB"
        or "ITWOM Version 3.0 path loss: XXX.XX dB"
        """
        with open(report_path, 'r') as f:
            for line in f:
                # Prefer ITWOM/ITM loss over free-space
                if 'ITWOM' in line and 'path loss' in line.lower():
                    return TerrainPathLoss._extract_db(line)
                if 'ITM' in line and 'path loss' in line.lower():
                    return TerrainPathLoss._extract_db(line)
            # Fall back to free-space if ITM line not found
            f.seek(0)
            for line in f:
                if 'free space path loss' in line.lower():
                    return TerrainPathLoss._extract_db(line)
        return None

    @staticmethod
    def _extract_db(line: str) -> Optional[float]:
        """Extract a dB value from a report line like 'Something: 138.5 dB'."""
        parts = line.split()
        for i, part in enumerate(parts):
            if part.lower() == 'db' and i > 0:
                try:
                    return float(parts[i - 1])
                except ValueError:
                    pass
        return None

    def run_batch(self, sites: list[SplatSite], freq_list: list[float],
                  sdf_dir: str, work_dir: str) -> None:
        """Run SPLAT! for all site pairs at all frequencies.

        Results are stored in self._matrices and can be saved via save_csv().
        """
        os.makedirs(work_dir, exist_ok=True)

        # Write QTH files
        for site in sites:
            site.write_qth(work_dir)

        for freq in freq_list:
            if freq not in self._matrices:
                self._matrices[freq] = {}

            for tx in sites:
                tx_qth = os.path.join(work_dir, '%s.qth' % tx.site_id)
                if tx.site_id not in self._matrices[freq]:
                    self._matrices[freq][tx.site_id] = {}

                for rx in sites:
                    if tx.site_id == rx.site_id:
                        continue
                    rx_qth = os.path.join(work_dir, '%s.qth' % rx.site_id)
                    loss = self.run_splat_pair(tx_qth, rx_qth, freq, sdf_dir, work_dir)
                    if loss is not None:
                        self._matrices[freq][tx.site_id][rx.site_id] = loss
