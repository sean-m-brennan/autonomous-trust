#!/usr/bin/env bash
# Download SRTM 1-arc-second elevation tiles for Braxton County, WV
# and convert them to SPLAT! .sdf format.
#
# Braxton County spans roughly 38-39°N, 80-81°W, requiring tiles:
#   N38W081, N38W080
#
# NASA Earthdata Login is required (https://urs.earthdata.nasa.gov).
# Configure ~/.netrc:
#   machine urs.earthdata.nasa.gov login <user> password <pass>
#
# If automated download fails, place .hgt files manually in the SRTM
# directory and re-run.
#
# Usage:
#   bash download_srtm.sh [srtm_dir] [sdf_dir]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TILES="N38W081 N38W080"
SRTM_DIR="${1:-$SCRIPT_DIR/../data/srtm}"
SDF_DIR="${2:-$SCRIPT_DIR/../data/sdf}"

mkdir -p "$SRTM_DIR" "$SDF_DIR"

# NASA Earthdata Cloud — SRTM GL1 (1 arc-second, ~30m resolution)
BASE_URL="https://data.lpdaac.earthdatacloud.nasa.gov/lp-prod-protected/SRTMGL1.003"

download_tile() {
    local tile="$1"
    local hgt_file="${tile}.hgt"
    local zip_file="${tile}.SRTMGL1.hgt.zip"
    local url="${BASE_URL}/${tile}.SRTMGL1.hgt/${zip_file}"

    if [[ -f "$SRTM_DIR/$hgt_file" ]]; then
        echo "$tile: .hgt already exists, skipping download"
        return 0
    fi

    echo "Downloading $tile from NASA Earthdata Cloud ..."
    # NASA Earthdata requires redirect-following and .netrc auth against urs.earthdata.nasa.gov
    if curl -f -L -b ~/.urs_cookies -c ~/.urs_cookies --netrc-optional \
         -o "$SRTM_DIR/$zip_file" "$url"; then
        unzip -o "$SRTM_DIR/$zip_file" -d "$SRTM_DIR"
        rm -f "$SRTM_DIR/$zip_file"
    else
        echo "WARNING: Download failed for $tile."
        echo "  NASA Earthdata Login required (https://urs.earthdata.nasa.gov)."
        echo "  Setup ~/.netrc with:"
        echo "    machine urs.earthdata.nasa.gov login <user> password <pass>"
        echo "  Or download manually from:"
        echo "    $url"
        echo "  and place ${hgt_file} in $SRTM_DIR"
        return 1
    fi
}

convert_tile() {
    local tile="$1"
    local hgt_file="$SRTM_DIR/${tile}.hgt"
    local sdf_file="$SDF_DIR/${tile}.sdf"

    if [[ -f "$sdf_file" ]]; then
        echo "$tile: .sdf already exists, skipping conversion"
        return 0
    fi

    if [[ ! -f "$hgt_file" ]]; then
        echo "$tile: .hgt not found, cannot convert"
        return 1
    fi

    if ! command -v srtm2sdf &>/dev/null; then
        echo "Error: srtm2sdf not found. Run build_splat.sh first." >&2
        return 1
    fi

    echo "Converting $tile to SDF ..."
    # srtm2sdf writes output in the current directory
    (cd "$SDF_DIR" && srtm2sdf "$hgt_file")
}

echo "=== SRTM GL1 Download for Braxton County, WV ==="
echo "Tiles: $TILES"
echo "SRTM dir: $SRTM_DIR"
echo "SDF dir:  $SDF_DIR"
echo "Source:   NASA Earthdata Cloud (LP DAAC)"
echo ""

# Check for .netrc before attempting downloads
if ! grep -q 'urs.earthdata.nasa.gov' ~/.netrc 2>/dev/null; then
    echo "WARNING: ~/.netrc does not contain NASA Earthdata credentials."
    echo "  Add:  machine urs.earthdata.nasa.gov login <user> password <pass>"
    echo "  Register at: https://urs.earthdata.nasa.gov"
    echo ""
fi

FAILED=0
for tile in $TILES; do
    download_tile "$tile" || FAILED=$((FAILED + 1))
done

echo ""
echo "=== Converting to SPLAT! SDF format ==="
for tile in $TILES; do
    convert_tile "$tile" || true
done

echo ""
echo "=== Summary ==="
echo "HGT files:"
ls -la "$SRTM_DIR"/*.hgt 2>/dev/null || echo "  (none)"
echo "SDF files:"
ls -la "$SDF_DIR"/*.sdf 2>/dev/null || echo "  (none)"

if [[ $FAILED -gt 0 ]]; then
    echo ""
    echo "WARNING: $FAILED tile(s) failed to download. See instructions above."
    exit 1
fi
