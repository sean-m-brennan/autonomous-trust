/********************
 *  Copyright 2025 Sean M. Brennan and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 ********************/

function findFiber(id) {
    let element = document.getElementById(id);
    if (element == null) {
        console.info('No DOM element ' + id + ' exists');
        return null;
    }
    // WARNING: this is fragile since it depends on React internals
    let key = Object.keys(element).find(key=>
        key.startsWith("__reactFiber$") // react 17+
        || key.startsWith("__reactInternalInstance$") // react <17
    );
    let fiber = element[key];
    if (fiber == null)
        console.info('No React Fiber element exists at ' + id);
    return fiber;
}

function findSetProps(id, traverse = 0) {
    let fiber = findFiber(id);
    if (fiber == null) {
        return null;  // warning already emitted
    }
    let setProps = fiber.return.memoizedProps.setProps;
    if (typeof(setProps) == "undefined") {
        console.warn('Element ' + id + ' has no setProps function (not a React component)');
        return null;
    }
    return setProps;
}

export function change_data(id, property, value) {
    let props = {};
    props[property] = value;

    const setProps = findSetProps(id);
    if (setProps != null) {
        console.debug('Modify Dash properties ' + id + ' ' + property)
        setProps(props);
    }
}