let windowLoaded = async function () {
    if (document.readyState !== 'complete') {
        await new Promise(function(resolve) {
            window.addEventListener('load', resolve);
        })
    }
}

let society_animate = function (container, loops, faces, initial, extras=[]) {
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

    const randFace = function () {
        let r = Math.random();
        let f = 0;
        if (r > 0.85)
            f = 1;
        else if (r > 0.55)
            f = 2;
        return faces[f];
    }

    const swap = function (idx, prev, cur, speed=1) {
        let prev_elt = svgDoc.getElementById(prev + (idx + 1).toString());
        let cur_elt = svgDoc.getElementById(cur + (idx + 1).toString());
        prev_elt.style.transition = "opacity " + speed.toString() + "s linear";
        prev_elt.style.opacity = "0";
        cur_elt.style.transition = "opacity " + speed.toString() + "s linear";
        cur_elt.style.opacity = "1";
    }

    const optimization_step = async function (loop, state) {
        const interact = async function(duration, lastIdx) {
            let total = 0;
            while (total < to_ms(duration)) {
                let idx = randInt(0, lastIdx);
                let face = randFace();
                swap(idx, state[idx], face);
                state[idx] = face;
                total += to_ms(0.5);
                await sleep(to_ms(0.5));
            }
        }

        document.getElementById("rMode").style.opacity = '1';
        document.getElementById("rppMode").style.opacity = '0';
        await interact(10, 8);

        // trouble shows up
        for (let idx = 0; idx < 2; idx++) {
            let cur_elt = svgDoc.getElementById("ds" + (idx + 1).toString());
            cur_elt.style.transition = "opacity 1s linear";
            cur_elt.style.opacity = "1";
        }
        await sleep(to_ms(0.25));
        for (let idx = 7; idx < 9; idx++) {
            swap(idx, state[idx], 'u');
            state[idx] = 'u';
        }
        for (let idx = 4; idx < 7; idx++) {
            swap(idx, state[idx], 'n');
            state[idx] = 'n';
        }
        await interact(4, 3);

        // r prime
        document.getElementById("rMode").style.opacity = '0';
        document.getElementById("rppMode").style.opacity = '1';
        for (let idx = 7; idx < 9; idx++) {
            swap(idx, state[idx], 'p');
            state[idx] = 'p';
        }
        await sleep(to_ms(1));
        for (let idx = 0; idx < 2; idx++) {
            swap(idx, "ds", "dd");
        }
        await interact(2, 6);
        for (let idx = 0; idx < 2; idx++) {
            let cur_elt = svgDoc.getElementById("dd" + (idx + 1).toString());
            cur_elt.style.transition = "opacity 2s linear";
            cur_elt.style.opacity = "0";
        }
        await interact(4, 6);
        for (let idx = 7; idx < 9; idx++) {
            swap(idx, state[idx], 'n', 2);
            state[idx] = 'n';
        }
        await interact(1, 6);
        document.getElementById("rppMode").style.opacity = '0';
    }

    const prioritization_step = async function (loop, state) {
        // init at reputation
        for (let idx = 0; idx < 5; idx++) {
            swap(idx, 's', 'h', 0.01)
            state[idx] = 'h'
        }
        for (let idx = 4; idx < 9; idx++) {
            swap(idx, 'p', 'h', 0.01)
            state[idx] = 'h'
        }
        await sleep(to_ms(2));
        // phase in stealth
        for (let idx = 0; idx < 5; idx++) {
            swap(idx, state[idx], 's');
            state[idx] = 's';
            await sleep(to_ms(1));
        }
        await sleep(to_ms(1));
        // phase out stealth
        for (let idx = 4; idx >= 0; idx--) {
            swap(idx, state[idx], 'h');
            state[idx] = 'h';
            if (idx < 8)
                await sleep(to_ms(1));
        }
        // phase in enforce
        for (let idx = 8; idx > 3; idx--) {
            swap(idx, state[idx], 'p');
            state[idx] = 'p';
            await sleep(to_ms(1));
        }
        await sleep(to_ms(1));
        // phase out enforce
        for (let idx = 4; idx < 9; idx++) {
            swap(idx, state[idx], 'h');
            state[idx] = 'h';
            await sleep(to_ms(1));
        }
        await sleep(to_ms(1));
        // final balance
        swap(8, state[8], 'p', 2);
        state[8] = 'p';
        swap(5, state[5], 'p', 2);
        state[5] = 'p';
        swap(0, state[0], 's', 2);
        state[0] = 's';
        await sleep(to_ms(5));
    }

    return ({
        run: async function (step) {
            await windowLoaded();  // FIXME doesn't work

            let state = initial.slice();
            for (let l = 0; l < loops; l++) {
                for (let idx = 0; idx < initial.length; idx++)
                    swap(idx, state[idx], initial[idx])
                state = initial.slice();
                for (let elt of extras) {
                    let cur_elt = svgDoc.getElementById(elt);
                    cur_elt.style.transition = "opacity 0.1s linear";
                    cur_elt.style.opacity = "0";
                }
                if (l === 0 && step === "optimization")
                    await sleep(to_ms(2));

                if (step === "optimization")
                    await optimization_step(l, state)
                else if (step === "prioritization")
                    await prioritization_step(l, state)
                else {
                    console.log("Animation not implemented")
                    break
                }
            }
        }
    });
}