/* Row resize for the demo grid.
 *
 * Reads computed grid-template-rows on first drag, then rewrites it in
 * px while the user drags either of two handle divs. The handle
 * indices match the CSS template:
 *   row 0 = top panel row     (map/graph/log)
 *   row 1 = handle 1
 *   row 2 = middle panel row  (time/streams)
 *   row 3 = handle 2
 *   row 4 = bottom panel row  (detail)
 */
(function () {
    const MIN_PX = 60;          // never let a panel row collapse below this
    const HANDLE_PX = 8;        // matches the CSS row size for handle tracks

    function init() {
        const grid = document.querySelector('.demo-grid');
        const handles = grid && grid.querySelectorAll('.demo-row-handle');
        if (!grid || !handles || handles.length < 2) {
            // Layout not ready yet; retry next frame.
            requestAnimationFrame(init);
            return;
        }
        handles.forEach((h, i) => {
            // Two handles: i=0 sits between rows 0 and 2, i=1 between
            // rows 2 and 4.
            const aboveIdx = i === 0 ? 0 : 2;
            const belowIdx = i === 0 ? 2 : 4;
            h.addEventListener('mousedown', (e) =>
                startDrag(e, grid, h, aboveIdx, belowIdx));
        });
    }

    function readRowHeights(grid) {
        // getComputedStyle returns gridTemplateRows as a space-separated
        // px list (resolved from fr at layout time). Parse to numbers.
        const cs = getComputedStyle(grid);
        return cs.gridTemplateRows.split(' ')
            .map(parseFloat)
            .filter((v) => !Number.isNaN(v));
    }

    function writeRowHeights(grid, heights) {
        // Panels in px, handles forced back to their fixed size so a
        // pixel rounding drift can't slowly bloat the handle tracks.
        const parts = heights.map((h, i) =>
            (i === 1 || i === 3) ? `${HANDLE_PX}px` : `${Math.round(h)}px`);
        grid.style.gridTemplateRows = parts.join(' ');
    }

    function startDrag(e, grid, handle, aboveIdx, belowIdx) {
        e.preventDefault();
        const heights = readRowHeights(grid);
        if (heights.length < 5) return;
        const startY = e.clientY;
        const aboveStart = heights[aboveIdx];
        const belowStart = heights[belowIdx];
        handle.classList.add('is-dragging');
        const prevSelect = document.body.style.userSelect;
        document.body.style.userSelect = 'none';
        document.body.style.cursor = 'ns-resize';

        function onMove(ev) {
            const dy = ev.clientY - startY;
            // Clamp so neither neighboring panel collapses below MIN_PX.
            const clampedDy = Math.max(
                MIN_PX - aboveStart,
                Math.min(belowStart - MIN_PX, dy));
            heights[aboveIdx] = aboveStart + clampedDy;
            heights[belowIdx] = belowStart - clampedDy;
            writeRowHeights(grid, heights);
        }
        function onUp() {
            window.removeEventListener('mousemove', onMove);
            window.removeEventListener('mouseup', onUp);
            handle.classList.remove('is-dragging');
            document.body.style.userSelect = prevSelect;
            document.body.style.cursor = '';
        }
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', onUp);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
