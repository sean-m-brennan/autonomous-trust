import {change_data} from "./dash_modify";
import {BinaryDataMsg} from "./bindata"
import {Buffer} from 'buffer';


let SocketClient = {

	socket: null,

    refs: 0,

    ws_uri: function(port=5005) {
        const loc = window.location;
        let uri;
        if (loc.protocol === "https:") {
            uri = "wss:";
        } else {
            uri = "ws:";
        }
        uri += "//" + loc.hostname + ":" + port.toString() + "/";
        return uri;
    },

    handleWindowBeforeUnload: function(_) {
        if (SocketClient.socket != null)
            SocketClient.socket.send("disconnect");
    },

	connect: function(port=5005) {
		if (SocketClient.socket == null) {
			SocketClient.socket = new WebSocket(SocketClient.ws_uri(port));
            SocketClient.socket.binaryType = "arraybuffer";

            SocketClient.socket.onopen = function(_) {
                SocketClient.socket.send("connect");
            };
            SocketClient.socket.onclose = function(_) {
                SocketClient.socket = null;
            };
            window.addEventListener("beforeunload", SocketClient.handleWindowBeforeUnload);

			SocketClient.socket.onmessage = function(message) {
                let obj;
                try {
                    obj = JSON.parse(message.data);
                } catch {
                    obj = BinaryDataMsg.decode(new Uint8Array(message.data));
                }
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
                    case "video":
                        SocketClient.recvVideo(obj.elt_id, obj.data);
                        break;
                }
			};
		}
        SocketClient.refs++;
	},

	disconnect: function() {
        SocketClient.refs--;
        if (SocketClient.refs > 0)
            return
        window.removeEventListener("beforeunload", SocketClient.handleWindowBeforeUnload);
		if (SocketClient.socket != null) {
            SocketClient.socket.send("disconnect");
            SocketClient.socket.close();
        }
	},

    trigger: function(info) {
        // parameter is dict of elt id, event type, and params dict
        let element = document.getElementById(info['id']);
        if (element == null) {
            console.info('No DOM element ' + info['id'] + ' exists');
            return
        }
        let evt = new Event(info['eventType']);
        if (Object.keys(info).length > 2)
            evt = new CustomEvent(info['eventType'], info['params']);
        element.dispatchEvent(evt)
    },

	change: function(info) {
        // parameter is dict of elt id, property name, and value json
        for (const data of info) {
            change_data(data['id'], data['property'], data['value']);
        }
	},

    updateGraphFigure: function(fig_info) {
        // parameter is a 3-tuple of graph div id, go.Figure dict, and config dict
        let id = fig_info[0];
        let data = fig_info[1]['data'];
        let layout = fig_info[1]['layout'];
        let cfg = fig_info[2];
        if (document.getElementById(id) == null) {
            console.debug('New plotly figure ' + id)
            Plotly.newPlot(id, data, layout, cfg)  // We are using Dash, so should not to import Plotly
        } else {
            console.debug('Update plotly figure ' + id)
            Plotly.react(id, data, layout, cfg)
        }
    },

    recvVideo: function(id, data) {
        let image = document.getElementById(id);
        if (image == null) {
            console.info('No DOM element ' + id + ' exists');
            return
        }
        let buffer = Buffer.from(data, 'base64')
        image.src = URL.createObjectURL(new Blob(buffer))
        console.log('rcvd img')  // FIXME remove
    },
}

export {SocketClient};
