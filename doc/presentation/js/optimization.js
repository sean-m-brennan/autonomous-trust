async function optimization_animate(container) {
    const svgDoc = container.getSVGDocument();
    const to_ms = function (sec) {
        return sec * 1000.0;
    }
    const sleep = function (ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    const randInt = function (min, max) {
        return Math.floor(Math.random() * (max - min) + min);
    }
    const loops = 3;
    const faces = ['s', 'n', 'u'];
    const randFace = function () {
        let r = Math.random();
        let f = 0;
        if (r > 0.85)
            f = 1;
        else if (r > 0.55)
            f = 2;
        return faces[f];
    }
    let initial = ['n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n'];
    const swap = function(idx, prev, cur) {
        let prev_elt = svgDoc.getElementById(prev + (idx+1).toString());
        let cur_elt = svgDoc.getElementById(cur + (idx+1).toString());
        prev_elt.style.transition = "opacity 0.9s linear";
        prev_elt.style.opacity = "0";
        cur_elt.style.transition = "opacity 0.9s linear";
        cur_elt.style.opacity = "1";
    }

    for (let l=0; l < loops; l++) {
        document.getElementById("rMode").style.opacity = '1';
        document.getElementById("rppMode").style.opacity = '0';
        let state = initial.slice();
        for (let i=0; i < state.length; i++)
            swap(i, state[i], 'n');
        for (let elt of ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
            "u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9",
            "p8", "p9", "ds1", "ds2", "dd1", "dd2"]) {
            let cur_elt = svgDoc.getElementById(elt);
            cur_elt.style.transition = "opacity 0.1s linear";
            cur_elt.style.opacity = "0";
        }
        if (l === 0)
            await sleep(to_ms(2));

        let total = 0;
        while (total < to_ms(10)) {
            let idx = randInt(0, 8);
            let face = randFace();
            swap(idx, state[idx], face);
            state[idx] = face;
            total += to_ms(0.5);
            await sleep(to_ms(0.5));
        }

        // trouble shows up
        for (let idx=0; idx < 2; idx++) {
            let cur_elt = svgDoc.getElementById("ds" + (idx+1).toString());
            cur_elt.style.transition = "opacity 0.6s linear";
            cur_elt.style.opacity = "1";
        }
        await sleep(to_ms(0.25));
        for (let idx=7; idx < 9; idx++) {
            swap(idx, state[idx], 'u');
            state[idx] = 'u';
        }
        for (let idx=4; idx < 7; idx++) {
            swap(idx, state[idx], 'n');
            state[idx] = 'n';
        }
        total = 0;
        while (total < to_ms(4)) {
            let idx = randInt(0, 3);
            let face = randFace();
            swap(idx, state[idx], face);
            state[idx] = face;
            total += to_ms(0.5);
            await sleep(to_ms(0.5));
        }

        // r prime
        document.getElementById("rMode").style.opacity = '0';
        document.getElementById("rppMode").style.opacity = '1';
        for (let idx=7; idx < 9; idx++) {
            swap(idx, state[idx], 'p');
            state[idx] = 'p';
        }
        await sleep(to_ms(0.75));
        for (let idx=0; idx < 2; idx++) {
            swap(idx, "ds", "dd");
        }
        total = 0;
        while (total < to_ms(5)) {
            let idx = randInt(0, 6);
            let face = randFace();
            swap(idx, state[idx], face);
            state[idx] = face;
            total += to_ms(0.5);
            await sleep(to_ms(0.5));
        }
     }
}