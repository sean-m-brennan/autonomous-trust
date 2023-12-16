/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./src/lib/components/AsyncUpdate.react.js":
/*!*************************************************!*\
  !*** ./src/lib/components/AsyncUpdate.react.js ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ AsyncUpdate)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var prop_types__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! prop-types */ "prop-types");
/* harmony import */ var prop_types__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(prop_types__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _socketclient_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../socketclient.js */ "./src/lib/socketclient.js");
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }
function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor); } }
function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); Object.defineProperty(Constructor, "prototype", { writable: false }); return Constructor; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : String(i); }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); Object.defineProperty(subClass, "prototype", { writable: false }); if (superClass) _setPrototypeOf(subClass, superClass); }
function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }
function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = _getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = _getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return _possibleConstructorReturn(this, result); }; }
function _possibleConstructorReturn(self, call) { if (call && (_typeof(call) === "object" || typeof call === "function")) { return call; } else if (call !== void 0) { throw new TypeError("Derived constructors may only return object or undefined"); } return _assertThisInitialized(self); }
function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }
function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {})); return true; } catch (e) { return false; } }
function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf.bind() : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }



var AsyncUpdate = /*#__PURE__*/function (_Component) {
  _inherits(AsyncUpdate, _Component);
  var _super = _createSuper(AsyncUpdate);
  function AsyncUpdate(props) {
    var _this;
    _classCallCheck(this, AsyncUpdate);
    _this = _super.call(this, props);
    _this.state = {
      port: props.port
    };
    return _this;
  }
  _createClass(AsyncUpdate, [{
    key: "componentDidMount",
    value: function componentDidMount() {
      _socketclient_js__WEBPACK_IMPORTED_MODULE_2__.SocketClient.connect(this.state.port);
    }
  }, {
    key: "componentWillUnmount",
    value: function componentWillUnmount() {
      _socketclient_js__WEBPACK_IMPORTED_MODULE_2__.SocketClient.disconnect();
    }
  }, {
    key: "render",
    value: function render() {
      return /*#__PURE__*/react__WEBPACK_IMPORTED_MODULE_0___default().createElement("div", null);
    }
  }]);
  return AsyncUpdate;
}(react__WEBPACK_IMPORTED_MODULE_0__.Component);

AsyncUpdate.defaultProps = {
  port: 5005
};
AsyncUpdate.propTypes = {
  port: (prop_types__WEBPACK_IMPORTED_MODULE_1___default().number)
};

/***/ }),

/***/ "./src/lib/components/Trigger.react.js":
/*!*********************************************!*\
  !*** ./src/lib/components/Trigger.react.js ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Trigger)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var prop_types__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! prop-types */ "prop-types");
/* harmony import */ var prop_types__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(prop_types__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var react_dom__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! react-dom */ "react-dom");
/* harmony import */ var react_dom__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(react_dom__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _socketclient__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../socketclient */ "./src/lib/socketclient.js");
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }
function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor); } }
function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); Object.defineProperty(Constructor, "prototype", { writable: false }); return Constructor; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : String(i); }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); Object.defineProperty(subClass, "prototype", { writable: false }); if (superClass) _setPrototypeOf(subClass, superClass); }
function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }
function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = _getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = _getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return _possibleConstructorReturn(this, result); }; }
function _possibleConstructorReturn(self, call) { if (call && (_typeof(call) === "object" || typeof call === "function")) { return call; } else if (call !== void 0) { throw new TypeError("Derived constructors may only return object or undefined"); } return _assertThisInitialized(self); }
function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }
function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {})); return true; } catch (e) { return false; } }
function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf.bind() : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }




var Trigger = /*#__PURE__*/function (_Component) {
  _inherits(Trigger, _Component);
  var _super = _createSuper(Trigger);
  function Trigger(props) {
    var _this;
    _classCallCheck(this, Trigger);
    _this = _super.call(this, props);
    _this.state = {
      triggers: props.triggers
    };
    _this.handleEvent = _this.handleEvent.bind(_assertThisInitialized(_this));
    _this.state.triggers = 0;
    return _this;
  }
  _createClass(Trigger, [{
    key: "componentDidMount",
    value: function componentDidMount() {
      react_dom__WEBPACK_IMPORTED_MODULE_2___default().findDOMNode(this).addEventListener(this.props.eventType, this.handleEvent);
      _socketclient__WEBPACK_IMPORTED_MODULE_3__.SocketClient.connect(this.state.port);
    }
  }, {
    key: "componentWillUnmount",
    value: function componentWillUnmount() {
      _socketclient__WEBPACK_IMPORTED_MODULE_3__.SocketClient.disconnect();
      react_dom__WEBPACK_IMPORTED_MODULE_2___default().findDOMNode(this).removeEventListener(this.props.eventType, this.handleEvent);
    }
  }, {
    key: "handleEvent",
    value: function handleEvent(event) {
      if (event.target.id === this.props.id && event.type === this.props.eventType) this.state.triggers++;
      this.props.setProps({
        triggers: this.state.triggers
      });
      this.state.triggers = 0;
    }
  }, {
    key: "render",
    value: function render() {
      var id = this.props.id;
      return /*#__PURE__*/react__WEBPACK_IMPORTED_MODULE_0___default().createElement("div", {
        id: id
      });
    }
  }]);
  return Trigger;
}(react__WEBPACK_IMPORTED_MODULE_0__.Component);

Trigger.defaultProps = {
  triggers: 0
};
Trigger.propTypes = {
  id: (prop_types__WEBPACK_IMPORTED_MODULE_1___default().string),
  eventType: (prop_types__WEBPACK_IMPORTED_MODULE_1___default().string),
  triggers: (prop_types__WEBPACK_IMPORTED_MODULE_1___default().number),
  /**
   * Dash-assigned callback that should be called to report property changes
   * to Dash, to make them available for callbacks.
   */
  setProps: (prop_types__WEBPACK_IMPORTED_MODULE_1___default().func)
};

/***/ }),

/***/ "./src/lib/dash_modify.js":
/*!********************************!*\
  !*** ./src/lib/dash_modify.js ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   change_data: () => (/* binding */ change_data)
/* harmony export */ });
function findFiber(id) {
  var element = document.getElementById(id);
  if (element == null) {
    console.info('No DOM element ' + id + ' exists');
    return null;
  }
  // WARNING: this is fragile since it depends on React internals
  var key = Object.keys(element).find(function (key) {
    return key.startsWith("__reactFiber$") // react 17+
    || key.startsWith("__reactInternalInstance$");
  } // react <17
  );
  var fiber = element[key];
  if (fiber == null) console.info('No React Fiber element exists at ' + id);
  return fiber;
}
function findSetProps(id) {
  var traverse = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;
  var fiber = findFiber(id);
  if (fiber == null) {
    return null; // warning already emitted
  }
  var setProps = fiber["return"].memoizedProps.setProps;
  if (typeof setProps == "undefined") {
    console.warn('Element ' + id + ' has no setProps function (not a React component)');
    return null;
  }
  return setProps;
}
function change_data(id, property, value) {
  var props = {};
  props[property] = value;
  var setProps = findSetProps(id);
  if (setProps != null) {
    console.debug('Modify Dash properties ' + id + ' ' + property);
    setProps(props);
  }
}

/***/ }),

/***/ "./src/lib/socketclient.js":
/*!*********************************!*\
  !*** ./src/lib/socketclient.js ***!
  \*********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   SocketClient: () => (/* binding */ SocketClient)
/* harmony export */ });
/* harmony import */ var _dash_modify__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./dash_modify */ "./src/lib/dash_modify.js");
function _createForOfIteratorHelper(o, allowArrayLike) { var it = typeof Symbol !== "undefined" && o[Symbol.iterator] || o["@@iterator"]; if (!it) { if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") { if (it) o = it; var i = 0; var F = function F() {}; return { s: F, n: function n() { if (i >= o.length) return { done: true }; return { done: false, value: o[i++] }; }, e: function e(_e) { throw _e; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var normalCompletion = true, didErr = false, err; return { s: function s() { it = it.call(o); }, n: function n() { var step = it.next(); normalCompletion = step.done; return step; }, e: function e(_e2) { didErr = true; err = _e2; }, f: function f() { try { if (!normalCompletion && it["return"] != null) it["return"](); } finally { if (didErr) throw err; } } }; }
function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }
function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i]; return arr2; }

var SocketClient = {
  socket: null,
  refs: 0,
  ws_uri: function ws_uri() {
    var port = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 5005;
    var loc = window.location;
    var uri;
    if (loc.protocol === "https:") {
      uri = "wss:";
    } else {
      uri = "ws:";
    }
    uri += "//" + loc.hostname + ":" + port.toString() + "/";
    return uri;
  },
  handleWindowBeforeUnload: function handleWindowBeforeUnload(_) {
    if (SocketClient.socket != null) SocketClient.socket.send("disconnect");
  },
  connect: function connect() {
    var port = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 5005;
    if (SocketClient.socket == null) {
      SocketClient.socket = new WebSocket(SocketClient.ws_uri(port));
      SocketClient.socket.onopen = function (_) {
        SocketClient.socket.send("connect");
      };
      SocketClient.socket.onclose = function (_) {
        SocketClient.socket = null;
      };
      window.addEventListener("beforeunload", SocketClient.handleWindowBeforeUnload);
      SocketClient.socket.onmessage = function (message) {
        var obj = JSON.parse(message.data);
        switch (obj.event) {
          case "modify":
            SocketClient.change(obj.data);
            break;
          case "update_figure":
            SocketClient.updateGraphFigure(obj.data);
            break;
          case "trigger_event":
            SocketClient.trigger(obj.data);
            break;
        }
      };
    }
    SocketClient.refs++;
  },
  disconnect: function disconnect() {
    SocketClient.refs--;
    if (SocketClient.refs > 0) return;
    window.removeEventListener("beforeunload", SocketClient.handleWindowBeforeUnload);
    if (SocketClient.socket != null) {
      SocketClient.socket.send("disconnect");
      SocketClient.socket.close();
    }
  },
  trigger: function trigger(info) {
    // parameter is dict of elt id, event type, and params dict
    var element = document.getElementById(info['id']);
    if (element == null) {
      console.info('No DOM element ' + info['id'] + ' exists');
    }
    var evt = new Event(info['eventType']);
    if (Object.keys(info).length > 2) evt = new CustomEvent(info['eventType'], info['params']);
    element.dispatchEvent(evt);
  },
  change: function change(info) {
    // parameter is dict of elt id, property name, and value json
    var _iterator = _createForOfIteratorHelper(info),
      _step;
    try {
      for (_iterator.s(); !(_step = _iterator.n()).done;) {
        var data = _step.value;
        (0,_dash_modify__WEBPACK_IMPORTED_MODULE_0__.change_data)(data['id'], data['property'], data['value']);
      }
    } catch (err) {
      _iterator.e(err);
    } finally {
      _iterator.f();
    }
  },
  updateGraphFigure: function updateGraphFigure(fig_info) {
    // parameter is a 3-tuple of graph div id, go.Figure dict, and config dict
    var id = fig_info[0];
    var data = fig_info[1]['data'];
    var layout = fig_info[1]['layout'];
    var cfg = fig_info[2];
    if (document.getElementById(id) == null) {
      console.debug('New plotly figure ' + id);
      Plotly.newPlot(id, data, layout, cfg);
    } else {
      console.debug('Update plotly figure ' + id);
      Plotly.react(id, data, layout, cfg);
    }
  }
};


/***/ }),

/***/ "prop-types":
/*!****************************!*\
  !*** external "PropTypes" ***!
  \****************************/
/***/ ((module) => {

module.exports = window["PropTypes"];

/***/ }),

/***/ "react":
/*!************************!*\
  !*** external "React" ***!
  \************************/
/***/ ((module) => {

module.exports = window["React"];

/***/ }),

/***/ "react-dom":
/*!***************************!*\
  !*** external "ReactDOM" ***!
  \***************************/
/***/ ((module) => {

module.exports = window["ReactDOM"];

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/compat */
/******/ 	var getCurrentScript = function() {
/******/ 	    var script = document.currentScript;
/******/ 	    if (!script) {
/******/ 	        /* Shim for IE11 and below */
/******/ 	        /* Do not take into account async scripts and inline scripts */
/******/ 	
/******/ 	        var doc_scripts = document.getElementsByTagName('script');
/******/ 	        var scripts = [];
/******/ 	
/******/ 	        for (var i = 0; i < doc_scripts.length; i++) {
/******/ 	            scripts.push(doc_scripts[i]);
/******/ 	        }
/******/ 	
/******/ 	        scripts = scripts.filter(function(s) { return !s.async && !s.text && !s.textContent; });
/******/ 	        script = scripts.slice(-1)[0];
/******/ 	    }
/******/ 	
/******/ 	    return script;
/******/ 	};
/******/ 	
/******/ 	var isLocalScript = function(script) {
/******/ 	    return /\/_dash-component-suites\//.test(script.src);
/******/ 	};
/******/ 	
/******/ 	Object.defineProperty(__webpack_require__, 'p', {
/******/ 	    get: (function () {
/******/ 	        var script = getCurrentScript();
/******/ 	
/******/ 	        var url = script.src.split('/').slice(0, -1).join('/') + '/';
/******/ 	
/******/ 	        return function() {
/******/ 	            return url;
/******/ 	        };
/******/ 	    })()
/******/ 	});
/******/ 	
/******/ 	if (typeof jsonpScriptSrc !== 'undefined') {
/******/ 	    var __jsonpScriptSrc__ = jsonpScriptSrc;
/******/ 	    jsonpScriptSrc = function(chunkId) {
/******/ 	        var script = getCurrentScript();
/******/ 	        var isLocal = isLocalScript(script);
/******/ 	
/******/ 	        var src = __jsonpScriptSrc__(chunkId);
/******/ 	
/******/ 	        if(!isLocal) {
/******/ 	            return src;
/******/ 	        }
/******/ 	
/******/ 	        var srcFragments = src.split('/');
/******/ 	        var fileFragments = srcFragments.slice(-1)[0].split('.');
/******/ 	
/******/ 	        fileFragments.splice(1, 0, "v0_0_1m1702693061");
/******/ 	        srcFragments.splice(-1, 1, fileFragments.join('.'))
/******/ 	
/******/ 	        return srcFragments.join('/');
/******/ 	    };
/******/ 	}
/******/ 	
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
/*!**************************!*\
  !*** ./src/lib/index.js ***!
  \**************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AsyncUpdate: () => (/* reexport safe */ _components_AsyncUpdate_react__WEBPACK_IMPORTED_MODULE_0__["default"]),
/* harmony export */   Trigger: () => (/* reexport safe */ _components_Trigger_react__WEBPACK_IMPORTED_MODULE_1__["default"])
/* harmony export */ });
/* harmony import */ var _components_AsyncUpdate_react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./components/AsyncUpdate.react */ "./src/lib/components/AsyncUpdate.react.js");
/* harmony import */ var _components_Trigger_react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./components/Trigger.react */ "./src/lib/components/Trigger.react.js");
/* eslint-disable import/prefer-default-export */



})();

window.async_update = __webpack_exports__;
/******/ })()
;
//# sourceMappingURL=async_update.dev.js.map